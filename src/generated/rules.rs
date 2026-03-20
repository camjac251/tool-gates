//! Auto-generated from rules/*.toml files.
//! DO NOT EDIT - changes will be overwritten by build.rs

#![allow(dead_code)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::nonminimal_bool)]

use crate::models::{CommandInfo, GateResult};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// Safe commands that are always allowed
pub static SAFE_COMMANDS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "[",
        "[[",
        "arp",
        "b2sum",
        "base64",
        "basename",
        "bat",
        "batcat",
        "bc",
        "btop",
        "cal",
        "cat",
        "cd",
        "cheat",
        "choose",
        "cksum",
        "clinfo",
        "cloc",
        "cmp",
        "column",
        "comm",
        "cut",
        "date",
        "dc",
        "delta",
        "df",
        "diff",
        "difft",
        "dig",
        "dirname",
        "dirs",
        "du",
        "dust",
        "echo",
        "expand",
        "export",
        "expr",
        "eza",
        "factor",
        "false",
        "fd",
        "file",
        "find",
        "fmt",
        "fold",
        "free",
        "fselect",
        "fx",
        "fzf",
        "getconf",
        "getfacl",
        "glxinfo",
        "grep",
        "gron",
        "groups",
        "hash",
        "head",
        "help",
        "hexdump",
        "hexyl",
        "host",
        "hostname",
        "hostnamectl",
        "htop",
        "id",
        "ifconfig",
        "info",
        "iostat",
        "ip",
        "join",
        "jq",
        "less",
        "loc",
        "locale",
        "locate",
        "ls",
        "lsattr",
        "lsblk",
        "lscpu",
        "lsd",
        "lsmem",
        "lsof",
        "lspci",
        "lsusb",
        "man",
        "md5sum",
        "more",
        "mtr",
        "netstat",
        "nl",
        "nproc",
        "nslookup",
        "numbat",
        "od",
        "paste",
        "pastel",
        "pgrep",
        "pidof",
        "ping",
        "popd",
        "pr",
        "printenv",
        "printf",
        "procs",
        "ps",
        "pushd",
        "pwd",
        "read",
        "readlink",
        "realpath",
        "rev",
        "rg",
        "ripgrep",
        "route",
        "scc",
        "seq",
        "set",
        "sha1sum",
        "sha256sum",
        "sha512sum",
        "sleep",
        "sort",
        "ss",
        "stat",
        "strings",
        "tac",
        "tail",
        "tealdeer",
        "test",
        "tig",
        "tldr",
        "tokei",
        "top",
        "tr",
        "tracepath",
        "traceroute",
        "tree",
        "true",
        "type",
        "unalias",
        "uname",
        "unexpand",
        "uniq",
        "unrar",
        "uptime",
        "vainfo",
        "vdpauinfo",
        "vmstat",
        "w",
        "wait",
        "wc",
        "whereis",
        "which",
        "who",
        "whoami",
        "whois",
        "xdpyinfo",
        "xwininfo",
        "xxd",
        "yes",
        "yq",
        "z",
        "zi",
        "zipinfo",
        "zoxide",
    ]
    .into_iter()
    .collect()
});

/// Check if a command is in the safe commands list
pub fn check_safe_command(cmd: &CommandInfo) -> Option<GateResult> {
    // Strip path prefix to handle /usr/bin/cat etc.
    let program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);
    if SAFE_COMMANDS.contains(program) {
        Some(GateResult::allow())
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalAction {
    Skip,
    Ask,
    Block,
}

/// Conditional allow rules (program -> (flags that prevent allow, action))
pub static CONDITIONAL_ALLOW: LazyLock<HashMap<&str, (&[&str], ConditionalAction)>> =
    LazyLock::new(|| {
        [(
            "sed",
            (&["-i", "--in-place"] as &[&str], ConditionalAction::Ask),
        )]
        .into_iter()
        .collect()
    });

/// Check conditional allow rules
pub fn check_conditional_allow(cmd: &CommandInfo) -> Option<GateResult> {
    // Strip path prefix to handle /usr/bin/sed etc.
    let program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);
    if let Some((flags, action)) = CONDITIONAL_ALLOW.get(program) {
        let has_flag = cmd.args.iter().any(|arg| flags.contains(&arg.as_str()));
        if has_flag {
            match action {
                ConditionalAction::Skip => None,
                ConditionalAction::Ask => {
                    Some(GateResult::ask(format!("{}: in-place edit", cmd.program)))
                }
                ConditionalAction::Block => {
                    Some(GateResult::block(format!("{}: blocked", cmd.program)))
                }
            }
        } else {
            Some(GateResult::allow())
        }
    } else {
        None
    }
}

// === MCP-CLI (from mcp.toml) ===

pub static MCP_CLI_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "servers",
        "tools",
        "info",
        "grep",
        "resources",
        "read",
        "help",
    ]
    .into_iter()
    .collect()
});

/// Check mcp-cli commands declaratively
pub fn check_mcp_cli_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mcp-cli"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if MCP_CLI_ALLOW.contains(subcmd.as_str()) || MCP_CLI_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("mcp-cli: {}", subcmd_single)))
}

// === GH (from gh.toml) ===

pub static GH_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "issue view",
        "issue list",
        "issue status",
        "pr view",
        "pr list",
        "pr status",
        "pr diff",
        "pr checks",
        "pr develop",
        "repo view",
        "repo list",
        "search issues",
        "search prs",
        "search repos",
        "search commits",
        "search code",
        "status",
        "auth status",
        "auth token",
        "config get",
        "config list",
        "run list",
        "run view",
        "workflow list",
        "workflow view",
        "release list",
        "release view",
        "gist list",
        "gist view",
        "label list",
        "codespace list",
        "cs list",
        "ssh-key list",
        "gpg-key list",
        "extension list",
        "browse",
        "alias list",
        "cache list",
        "variable list",
        "secret list",
        "ruleset list",
        "ruleset view",
        "project list",
        "project view",
    ]
    .into_iter()
    .collect()
});

pub static GH_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("repo clone", "Cloning repo (writes to local filesystem)"),
        (
            "run download",
            "Downloading artifacts (writes to local filesystem)",
        ),
        (
            "release download",
            "Downloading release assets (writes to local filesystem)",
        ),
        ("gist clone", "Cloning gist (writes to local filesystem)"),
        ("issue create", "Creating issue"),
        ("issue close", "Closing issue"),
        ("issue reopen", "Reopening issue"),
        ("issue edit", "Editing issue"),
        ("issue comment", "Adding comment"),
        ("issue delete", "Deleting issue"),
        ("issue transfer", "Transferring issue"),
        ("issue pin", "Pinning issue"),
        ("issue unpin", "Unpinning issue"),
        ("issue lock", "Locking issue"),
        ("issue unlock", "Unlocking issue"),
        ("pr create", "Creating PR"),
        ("pr close", "Closing PR"),
        ("pr reopen", "Reopening PR"),
        ("pr edit", "Editing PR"),
        ("pr comment", "Adding comment"),
        ("pr merge", "Merging PR"),
        ("pr ready", "Marking PR ready"),
        ("pr review", "Submitting review"),
        ("pr checkout", "Checking out PR"),
        ("repo create", "Creating repository"),
        ("repo rename", "Renaming repository"),
        ("repo edit", "Editing repository"),
        ("repo fork", "Forking repository"),
        ("repo archive", "Archiving repository"),
        ("repo unarchive", "Unarchiving repository"),
        ("repo sync", "Syncing repository"),
        ("repo set-default", "Setting default repo"),
        ("release create", "Creating release"),
        ("release delete", "Deleting release"),
        ("release edit", "Editing release"),
        ("release upload", "Uploading asset"),
        ("release delete-asset", "Deleting asset"),
        ("gist create", "Creating gist"),
        ("gist delete", "Deleting gist"),
        ("gist edit", "Editing gist"),
        ("gist rename", "Renaming gist"),
        ("label create", "Creating label"),
        ("label delete", "Deleting label"),
        ("label edit", "Editing label"),
        ("label clone", "Cloning labels"),
        ("workflow run", "Running workflow"),
        ("workflow enable", "Enabling workflow"),
        ("workflow disable", "Disabling workflow"),
        ("run cancel", "Canceling run"),
        ("run rerun", "Rerunning"),
        ("run delete", "Deleting run"),
        ("run watch", "Watching run"),
        ("codespace create", "Creating codespace"),
        ("codespace delete", "Deleting codespace"),
        ("codespace edit", "Editing codespace"),
        ("codespace stop", "Stopping codespace"),
        ("codespace rebuild", "Rebuilding codespace"),
        ("cs create", "Creating codespace"),
        ("cs delete", "Deleting codespace"),
        ("ssh-key add", "Adding SSH key"),
        ("ssh-key delete", "Deleting SSH key"),
        ("gpg-key add", "Adding GPG key"),
        ("gpg-key delete", "Deleting GPG key"),
        ("config set", "Setting config"),
        ("config clear-cache", "Clearing cache"),
        ("secret set", "Setting secret"),
        ("secret delete", "Deleting secret"),
        ("variable set", "Setting variable"),
        ("variable delete", "Deleting variable"),
        ("cache delete", "Deleting cache"),
        ("extension install", "Installing extension"),
        ("extension upgrade", "Upgrading extension"),
        ("extension remove", "Removing extension"),
        ("alias set", "Setting alias"),
        ("alias delete", "Deleting alias"),
        ("alias import", "Importing aliases"),
        ("project create", "Creating project"),
        ("project delete", "Deleting project"),
        ("project edit", "Editing project"),
        ("project close", "Closing project"),
        ("project copy", "Copying project"),
        ("project item-add", "Adding project item"),
        ("project item-archive", "Archiving item"),
        ("project item-create", "Creating item"),
        ("project item-delete", "Deleting item"),
        ("project item-edit", "Editing item"),
        ("project field-create", "Creating field"),
        ("project field-delete", "Deleting field"),
    ]
    .into_iter()
    .collect()
});

pub static GH_BLOCK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("repo delete", "Deleting repositories is blocked"),
        ("auth logout", "Logging out is blocked"),
    ]
    .into_iter()
    .collect()
});

/// Check gh commands declaratively
pub fn check_gh_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["gh"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if let Some(reason) = GH_BLOCK.get(subcmd.as_str()) {
        return Some(GateResult::block(format!("gh: {}", reason)));
    }

    if GH_ALLOW.contains(subcmd.as_str()) || GH_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = GH_ASK
        .get(subcmd.as_str())
        .or_else(|| GH_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("gh: {}", reason)));
    }

    // API rules for 'gh api'
    if subcmd_single == "api" {
        let explicit_method = cmd
            .args
            .iter()
            .position(|a| ["-X", "--method"].contains(&a.as_str()))
            .and_then(|i| cmd.args.get(i + 1))
            .map(|s| s.to_uppercase());
        let endpoint = cmd
            .args
            .iter()
            .skip(1) // skip 'api'
            .find(|a| !a.starts_with('-'));
        let is_read_only_endpoint =
            endpoint.is_some_and(|e| ["search/"].iter().any(|p| e.starts_with(p)));
        let has_implicit_post = cmd.args.iter().any(|a| {
            let arg = a.as_str();
            ["-f", "-F", "--field", "--raw-field", "--input"]
                .iter()
                .any(|f| arg == *f || arg.starts_with(&format!("{}=", f)))
        });
        let method = explicit_method.unwrap_or_else(|| {
            if is_read_only_endpoint {
                "GET".to_string()
            } else if has_implicit_post {
                "POST".to_string()
            } else {
                "GET".to_string()
            }
        });
        if ["GET"].contains(&method.as_str()) {
            return Some(GateResult::allow());
        }
        return Some(GateResult::ask(format!("gh api: {} request", method)));
    }

    Some(GateResult::ask(format!("gh: {}", subcmd_single)))
}

// === GIT (from git.toml) ===

pub static GIT_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "status",
        "log",
        "diff",
        "show",
        "describe",
        "rev-parse",
        "ls-files",
        "blame",
        "reflog",
        "shortlog",
        "whatchanged",
        "ls-tree",
        "cat-file",
        "rev-list",
        "name-rev",
        "for-each-ref",
        "symbolic-ref",
        "verify-commit",
        "verify-tag",
        "fsck",
        "count-objects",
        "check-ignore",
        "check-attr",
        "grep",
        "merge-base",
        "show-ref",
        "help",
        "version",
        "--version",
        "-h",
        "--help",
        "config get",
        "config list",
        "config --get",
        "config --list",
        "stash list",
        "stash show",
        "worktree list",
        "submodule status",
        "remote show",
        "remote -v",
        "remote get-url",
    ]
    .into_iter()
    .collect()
});

pub static GIT_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("gc", "Garbage collection (modifies .git directory)"),
        ("prune", "Pruning objects (deletes from .git directory)"),
        ("config set", "git config set"),
        ("config --add", "git config --add"),
        ("config --unset", "git config --unset"),
        ("stash drop", "git stash drop"),
        ("stash pop", "git stash pop"),
        ("stash clear", "git stash clear"),
        ("stash push", "git stash push"),
        ("stash apply", "git stash apply"),
        ("worktree add", "git worktree add"),
        ("worktree remove", "git worktree remove"),
        ("worktree prune", "git worktree prune"),
        (
            "submodule foreach",
            "git submodule foreach (runs arbitrary commands)",
        ),
        ("submodule init", "git submodule init"),
        ("submodule update", "git submodule update"),
        ("submodule add", "git submodule add"),
        ("submodule deinit", "git submodule deinit"),
        ("remote add", "git remote add"),
        ("remote remove", "git remote remove"),
        ("remote rename", "git remote rename"),
        ("remote set-url", "git remote set-url"),
        ("commit", "Committing changes"),
        ("push", "Pushing to remote"),
        ("pull", "Pulling from remote"),
        ("merge", "Merging branches"),
        ("rebase", "Rebasing"),
        ("checkout", "Checking out"),
        ("switch", "Switching branches"),
        ("reset", "Resetting"),
        ("restore", "Restoring files"),
        ("clean", "Cleaning working tree"),
        ("cherry-pick", "Cherry-picking"),
        ("revert", "Reverting commits"),
        ("am", "Applying patches"),
        ("apply", "Applying patches"),
        ("format-patch", "Creating patches"),
        ("init", "Initializing repo"),
        ("clone", "Cloning repo"),
        ("fetch", "Fetching"),
        ("mv", "Moving files"),
        ("rm", "Removing files"),
        ("bisect", "Starting bisect session"),
        ("filter-branch", "Rewriting history (dangerous)"),
        ("filter-repo", "Rewriting history (dangerous)"),
        ("notes", "git notes operation"),
        ("bundle", "Bundle operation"),
        (
            "maintenance",
            "Running maintenance tasks (modifies .git directory)",
        ),
        ("sparse-checkout", "Modifying sparse checkout"),
        ("worktree", "git worktree operation"),
    ]
    .into_iter()
    .collect()
});

/// Check git commands declaratively
pub fn check_git_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["git"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Check allow_if_flags (e.g., --dry-run)
    if cmd
        .args
        .iter()
        .any(|a| ["--dry-run", "-n"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if subcmd_single == "push"
        && cmd
            .args
            .iter()
            .any(|a| ["--force", "-f"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Force push (safer: --force-with-lease)"));
    }
    if subcmd_single == "reset" && cmd.args.iter().any(|a| ["--hard"].contains(&a.as_str())) {
        return Some(GateResult::ask("Hard reset (can lose uncommitted work)"));
    }
    if subcmd_single == "clean"
        && cmd
            .args
            .iter()
            .any(|a| ["-fd", "-fdx", "-f"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Clean (deletes untracked files permanently)",
        ));
    }
    if subcmd_single == "checkout" && cmd.args.iter().any(|a| ["-b", "-B"].contains(&a.as_str())) {
        return Some(GateResult::ask("Creating branch"));
    }
    if subcmd_single == "checkout" && cmd.args.iter().any(|a| ["--"].contains(&a.as_str())) {
        return Some(GateResult::ask("Discarding changes"));
    }
    if subcmd_single == "tag"
        && cmd.args.iter().any(|a| {
            [
                "-a",
                "--annotate",
                "-s",
                "--sign",
                "-u",
                "--local-user",
                "-m",
                "--message",
            ]
            .contains(&a.as_str())
        })
    {
        return Some(GateResult::ask("Creating tag"));
    }
    if subcmd_single == "tag"
        && cmd
            .args
            .iter()
            .any(|a| ["-d", "--delete"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Deleting tag"));
    }
    if subcmd_single == "tag"
        && cmd
            .args
            .iter()
            .any(|a| ["-f", "--force"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Force-replacing tag"));
    }
    if subcmd_single == "branch"
        && cmd
            .args
            .iter()
            .any(|a| ["-d", "-D", "--delete"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Deleting branch"));
    }
    if subcmd_single == "branch"
        && cmd
            .args
            .iter()
            .any(|a| ["-m", "-M", "--move"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Renaming branch"));
    }

    if GIT_ALLOW.contains(subcmd.as_str()) || GIT_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "tag"
        && !cmd.args.iter().any(|a| {
            [
                "-d",
                "--delete",
                "-f",
                "--force",
                "-a",
                "--annotate",
                "-s",
                "--sign",
                "-u",
                "--local-user",
                "-m",
                "--message",
            ]
            .contains(&a.as_str())
        })
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "branch"
        && !cmd.args.iter().any(|a| {
            [
                "-d", "-D", "--delete", "-m", "-M", "--move", "-c", "-C", "--copy",
            ]
            .contains(&a.as_str())
        })
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "remote"
        && !cmd
            .args
            .iter()
            .any(|a| ["add", "remove", "rename", "set-url"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    if let Some(reason) = GIT_ASK
        .get(subcmd.as_str())
        .or_else(|| GIT_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("git: {}", reason)));
    }

    Some(GateResult::ask(format!("git: {}", subcmd_single)))
}

// === AWS (from cloud.toml) ===

pub static AWS_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "--version",
        "help",
        "s3 ls",
        "sts get-caller-identity",
        "sts get-session-token",
        "configure list",
    ]
    .into_iter()
    .collect()
});

pub static AWS_BLOCK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [("iam delete-user", "Deleting IAM users is blocked")]
        .into_iter()
        .collect()
});

/// Check aws commands declaratively
pub fn check_aws_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["aws"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if let Some(reason) = AWS_BLOCK.get(subcmd.as_str()) {
        return Some(GateResult::block(format!("aws: {}", reason)));
    }

    // Check conditional block rules
    if subcmd.starts_with("organizations delete") {
        return Some(GateResult::block("aws: Organization deletion blocked"));
    }

    // Check ask rules with flag/prefix conditions
    if cmd.args.get(1).is_some_and(|a| a.starts_with("create")) {
        return Some(GateResult::ask("aws: Creating resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("delete")) {
        return Some(GateResult::ask("aws: Deleting resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("put")) {
        return Some(GateResult::ask("aws: Writing resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("update")) {
        return Some(GateResult::ask("aws: Updating resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("modify")) {
        return Some(GateResult::ask("aws: Modifying resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("remove")) {
        return Some(GateResult::ask("aws: Removing resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("run")) {
        return Some(GateResult::ask("aws: Running resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("start")) {
        return Some(GateResult::ask("aws: Starting resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("stop")) {
        return Some(GateResult::ask("aws: Stopping resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("terminate")) {
        return Some(GateResult::ask("aws: Terminating resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("reboot")) {
        return Some(GateResult::ask("aws: Rebooting resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("attach")) {
        return Some(GateResult::ask("aws: Attaching resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("detach")) {
        return Some(GateResult::ask("aws: Detaching resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("associate")) {
        return Some(GateResult::ask("aws: Associating resources"));
    }
    if cmd
        .args
        .get(1)
        .is_some_and(|a| a.starts_with("disassociate"))
    {
        return Some(GateResult::ask("aws: Disassociating resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("enable")) {
        return Some(GateResult::ask("aws: Enabling resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("disable")) {
        return Some(GateResult::ask("aws: Disabling resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("register")) {
        return Some(GateResult::ask("aws: Registering resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("deregister")) {
        return Some(GateResult::ask("aws: Deregistering resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("invoke")) {
        return Some(GateResult::ask("aws: Invoking resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("publish")) {
        return Some(GateResult::ask("aws: Publishing resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("send")) {
        return Some(GateResult::ask("aws: Sending messages"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("tag")) {
        return Some(GateResult::ask("aws: Tagging resources"));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("untag")) {
        return Some(GateResult::ask("aws: Untagging resources"));
    }

    if AWS_ALLOW.contains(subcmd.as_str()) || AWS_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if cmd.args.get(1).is_some_and(|a| a.starts_with("describe")) {
        return Some(GateResult::allow());
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("list")) {
        return Some(GateResult::allow());
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("get")) {
        return Some(GateResult::allow());
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("head")) {
        return Some(GateResult::allow());
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("query")) {
        return Some(GateResult::allow());
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("scan")) {
        return Some(GateResult::allow());
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("filter")) {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("aws: {}", subcmd_single)))
}

// === GCLOUD (from cloud.toml) ===

pub static GCLOUD_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "config list",
        "config get-value",
        "auth list",
        "auth describe",
        "projects list",
        "projects describe",
        "compute instances list",
        "compute instances describe",
        "compute zones list",
        "compute regions list",
        "compute machine-types list",
        "container clusters list",
        "container clusters describe",
        "storage ls",
        "storage cat",
        "functions list",
        "functions describe",
        "functions logs",
        "run services list",
        "run services describe",
        "sql instances list",
        "sql instances describe",
        "logging read",
        "iam list",
        "iam describe",
        "secrets list",
        "secrets describe",
        "secrets versions",
        "--version",
        "help",
        "info",
    ]
    .into_iter()
    .collect()
});

pub static GCLOUD_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        (
            "container clusters get-credentials",
            "Updating kubeconfig (writes to ~/.kube/config)",
        ),
        ("compute instances create", "Compute create"),
        ("compute instances delete", "Compute delete"),
        ("compute instances start", "Compute start"),
        ("compute instances stop", "Compute stop"),
        ("compute instances reset", "Compute reset"),
        ("container clusters create", "GKE create"),
        ("container clusters delete", "GKE delete"),
        ("container clusters resize", "GKE resize"),
        ("container clusters upgrade", "GKE upgrade"),
        ("storage cp", "Storage copy"),
        ("storage mv", "Storage move"),
        ("storage rm", "Storage delete"),
        ("functions deploy", "Functions deploy"),
        ("functions delete", "Functions delete"),
        ("run deploy", "Cloud Run deploy"),
        ("run services delete", "Cloud Run delete"),
        ("sql instances create", "Cloud SQL create"),
        ("sql instances delete", "Cloud SQL delete"),
        ("sql instances patch", "Cloud SQL patch"),
        ("secrets create", "Secrets create"),
        ("secrets delete", "Secrets delete"),
        ("projects create", "Project create"),
        ("projects delete", "Project delete"),
    ]
    .into_iter()
    .collect()
});

/// Check gcloud commands declaratively
pub fn check_gcloud_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["gcloud"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if GCLOUD_ALLOW.contains(subcmd.as_str()) || GCLOUD_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = GCLOUD_ASK
        .get(subcmd.as_str())
        .or_else(|| GCLOUD_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("gcloud: {}", reason)));
    }

    Some(GateResult::ask(format!("gcloud: {}", subcmd_single)))
}

// === AZ (from cloud.toml) ===

pub static AZ_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "--help", "-h"].into_iter().collect());

/// Check az commands declaratively
pub fn check_az_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["az"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if AZ_ALLOW.contains(subcmd.as_str()) || AZ_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("az: {}", subcmd_single)))
}

// === TERRAFORM (from cloud.toml) ===

pub static TERRAFORM_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "plan",
        "show",
        "output",
        "validate",
        "version",
        "providers",
        "graph",
        "-version",
        "--version",
        "-help",
        "--help",
        "state list",
        "state show",
        "workspace list",
    ]
    .into_iter()
    .collect()
});

pub static TERRAFORM_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("apply", "Terraform: Applying changes"),
        ("destroy", "Terraform: Destroying infrastructure"),
        ("import", "Terraform: Importing resource"),
        ("taint", "Terraform: Tainting resource"),
        ("untaint", "Terraform: Untainting resource"),
        ("init", "Terraform: Initializing"),
        ("fmt", "Terraform: Formatting files"),
        ("state mv", "Terraform: state mv"),
        ("state rm", "Terraform: state rm"),
        ("state push", "Terraform: state push"),
        ("state pull", "Terraform: state pull"),
        ("workspace new", "Terraform: workspace new"),
        ("workspace delete", "Terraform: workspace delete"),
        ("workspace select", "Terraform: workspace select"),
    ]
    .into_iter()
    .collect()
});

/// Check terraform commands declaratively
pub fn check_terraform_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["terraform", "tofu"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if TERRAFORM_ALLOW.contains(subcmd.as_str()) || TERRAFORM_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "fmt" && cmd.args.iter().any(|a| ["-check"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = TERRAFORM_ASK
        .get(subcmd.as_str())
        .or_else(|| TERRAFORM_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("terraform: {}", reason)));
    }

    Some(GateResult::ask(format!("terraform: {}", subcmd_single)))
}

// === KUBECTL (from cloud.toml) ===

pub static KUBECTL_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "get",
        "describe",
        "logs",
        "top",
        "explain",
        "api-resources",
        "api-versions",
        "cluster-info",
        "version",
        "-h",
        "--help",
        "config view",
        "config get-contexts",
        "config current-context",
        "config get-clusters",
        "auth can-i",
        "auth whoami",
    ]
    .into_iter()
    .collect()
});

pub static KUBECTL_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("apply", "Applying resources"),
        ("create", "Creating resources"),
        ("delete", "Deleting resources"),
        ("edit", "Editing resources"),
        ("patch", "Patching resources"),
        ("replace", "Replacing resources"),
        ("scale", "Scaling resources"),
        ("rollout", "Rollout operation"),
        ("expose", "Exposing service"),
        ("run", "Running pod"),
        ("exec", "Executing in pod"),
        ("cp", "Copying files"),
        ("port-forward", "Port forwarding"),
        ("label", "Labeling resources"),
        ("annotate", "Annotating resources"),
        ("taint", "Tainting nodes"),
        ("drain", "Draining nodes"),
        ("cordon", "Cordoning nodes"),
        ("uncordon", "Uncordoning nodes"),
        ("config set-context", "config set-context"),
        ("config use-context", "config use-context"),
        ("config set-cluster", "config set-cluster"),
        ("config set-credentials", "config set-credentials"),
        ("config delete-context", "config delete-context"),
        ("config delete-cluster", "config delete-cluster"),
    ]
    .into_iter()
    .collect()
});

pub static KUBECTL_BLOCK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("delete namespace kube-system", "Cannot delete kube-system"),
        ("delete ns kube-system", "Cannot delete kube-system"),
    ]
    .into_iter()
    .collect()
});

/// Check kubectl commands declaratively
pub fn check_kubectl_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["kubectl", "k"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if let Some(reason) = KUBECTL_BLOCK.get(subcmd.as_str()) {
        return Some(GateResult::block(format!("kubectl: {}", reason)));
    }

    if KUBECTL_ALLOW.contains(subcmd.as_str()) || KUBECTL_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = KUBECTL_ASK
        .get(subcmd.as_str())
        .or_else(|| KUBECTL_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("kubectl: {}", reason)));
    }

    Some(GateResult::ask(format!("kubectl: {}", subcmd_single)))
}

// === DOCKER (from cloud.toml) ===

pub static DOCKER_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "ps",
        "images",
        "inspect",
        "logs",
        "stats",
        "top",
        "port",
        "version",
        "info",
        "history",
        "-v",
        "--version",
        "-h",
        "--help",
        "network ls",
        "network list",
        "network inspect",
        "volume ls",
        "volume list",
        "volume inspect",
        "system df",
        "system info",
        "compose ps",
        "compose logs",
        "compose config",
        "compose images",
        "compose ls",
        "compose version",
        "compose top",
    ]
    .into_iter()
    .collect()
});

pub static DOCKER_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("compose up", "Compose: Starting services"),
        ("compose down", "Compose: Stopping services"),
        ("compose start", "Compose: Starting services"),
        ("compose stop", "Compose: Stopping services"),
        ("compose restart", "Compose: Restarting services"),
        ("compose build", "Compose: Building images"),
        ("compose pull", "Compose: Pulling images"),
        ("compose push", "Compose: Pushing images"),
        ("compose exec", "Compose: Executing in container"),
        ("compose run", "Compose: Running command"),
        ("compose rm", "Compose: Removing containers"),
        ("compose create", "Compose: Creating containers"),
        ("compose kill", "Compose: Killing containers"),
        ("compose pause", "Compose: Pausing containers"),
        ("compose unpause", "Compose: Unpausing containers"),
        ("run", "Docker: Running container"),
        ("exec", "Docker: Executing in container"),
        ("build", "Docker: Building image"),
        ("push", "Docker: Pushing image"),
        ("pull", "Docker: Pulling image"),
        ("rm", "Docker: Removing container"),
        ("rmi", "Docker: Removing image"),
        ("kill", "Docker: Killing container"),
        ("stop", "Docker: Stopping container"),
        ("start", "Docker: Starting container"),
        ("restart", "Docker: Restarting container"),
        ("pause", "Docker: Pausing container"),
        ("unpause", "Docker: Unpausing container"),
        ("tag", "Docker: Tagging image"),
        ("commit", "Docker: Committing container"),
        ("cp", "Docker: Copying files"),
        ("login", "Docker: Logging in"),
        ("logout", "Docker: Logging out"),
        ("network create", "Docker: network create"),
        ("network rm", "Docker: network rm"),
        ("network connect", "Docker: network connect"),
        ("network disconnect", "Docker: network disconnect"),
        ("volume create", "Docker: volume create"),
        ("volume rm", "Docker: volume rm"),
        ("system prune", "Docker: system prune"),
    ]
    .into_iter()
    .collect()
});

/// Check docker commands declaratively
pub fn check_docker_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["docker"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if DOCKER_ALLOW.contains(subcmd.as_str()) || DOCKER_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = DOCKER_ASK
        .get(subcmd.as_str())
        .or_else(|| DOCKER_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("docker: {}", reason)));
    }

    Some(GateResult::ask(format!("docker: {}", subcmd_single)))
}

// === PODMAN (from cloud.toml) ===

pub static PODMAN_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "ps",
        "images",
        "inspect",
        "logs",
        "stats",
        "top",
        "port",
        "version",
        "info",
        "history",
        "search",
        "healthcheck",
        "-v",
        "--version",
        "-h",
        "--help",
        "network ls",
        "network list",
        "network inspect",
        "volume ls",
        "volume list",
        "volume inspect",
        "system df",
        "system info",
        "machine info",
        "machine inspect",
        "machine list",
        "pod ps",
        "pod list",
        "pod inspect",
        "pod logs",
        "pod top",
        "pod stats",
        "secret ls",
        "secret list",
        "secret inspect",
    ]
    .into_iter()
    .collect()
});

pub static PODMAN_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("run", "Podman: Running container"),
        ("exec", "Podman: Executing in container"),
        ("build", "Podman: Building image"),
        ("push", "Podman: Pushing image"),
        ("pull", "Podman: Pulling image"),
        ("rm", "Podman: Removing container"),
        ("rmi", "Podman: Removing image"),
        ("kill", "Podman: Killing container"),
        ("stop", "Podman: Stopping container"),
        ("start", "Podman: Starting container"),
        ("restart", "Podman: Restarting container"),
        ("pause", "Podman: Pausing container"),
        ("unpause", "Podman: Unpausing container"),
        ("tag", "Podman: Tagging image"),
        ("commit", "Podman: Committing container"),
        ("cp", "Podman: Copying files"),
        ("login", "Podman: Logging in"),
        ("logout", "Podman: Logging out"),
        ("create", "Podman: Creating container"),
        ("pod", "Podman: Pod operation"),
        ("generate", "Podman: Generating config"),
        ("play", "Podman: Playing kube YAML"),
    ]
    .into_iter()
    .collect()
});

/// Check podman commands declaratively
pub fn check_podman_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["podman"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if PODMAN_ALLOW.contains(subcmd.as_str()) || PODMAN_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = PODMAN_ASK
        .get(subcmd.as_str())
        .or_else(|| PODMAN_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("podman: {}", reason)));
    }

    Some(GateResult::ask(format!("podman: {}", subcmd_single)))
}

// === DOCKER-COMPOSE (from cloud.toml) ===

pub static DOCKER_COMPOSE_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "ps", "logs", "config", "images", "ls", "version", "-h", "--help",
    ]
    .into_iter()
    .collect()
});

pub static DOCKER_COMPOSE_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("up", "Compose: Starting services"),
        ("down", "Compose: Stopping services"),
        ("start", "Compose: Starting services"),
        ("stop", "Compose: Stopping services"),
        ("restart", "Compose: Restarting services"),
        ("pause", "Compose: Pausing services"),
        ("unpause", "Compose: Unpausing services"),
        ("build", "Compose: Building services"),
        ("push", "Compose: Pushing images"),
        ("pull", "Compose: Pulling images"),
        ("rm", "Compose: Removing services"),
        ("kill", "Compose: Killing services"),
        ("exec", "Compose: Executing in service"),
        ("run", "Compose: Running one-off"),
        ("create", "Compose: Creating services"),
    ]
    .into_iter()
    .collect()
});

/// Check docker-compose commands declaratively
pub fn check_docker_compose_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["docker-compose", "podman-compose"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if DOCKER_COMPOSE_ALLOW.contains(subcmd.as_str())
        || DOCKER_COMPOSE_ALLOW.contains(subcmd_single)
    {
        return Some(GateResult::allow());
    }

    if let Some(reason) = DOCKER_COMPOSE_ASK
        .get(subcmd.as_str())
        .or_else(|| DOCKER_COMPOSE_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("docker-compose: {}", reason)));
    }

    Some(GateResult::ask(format!(
        "docker-compose: {}",
        subcmd_single
    )))
}

// === HELM (from cloud.toml) ===

pub static HELM_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list",
        "ls",
        "get",
        "show",
        "search",
        "repo list",
        "status",
        "history",
        "version",
        "-h",
        "--help",
        "template",
        "lint",
        "verify",
    ]
    .into_iter()
    .collect()
});

pub static HELM_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("repo add", "Adding chart repository"),
        ("repo remove", "Removing chart repository"),
        ("repo update", "Updating chart repositories"),
        ("install", "Helm: Installing release"),
        ("upgrade", "Helm: Upgrading release"),
        ("uninstall", "Helm: Uninstalling release"),
        ("rollback", "Helm: Rolling back"),
        ("delete", "Helm: Deleting release"),
        ("push", "Helm: Pushing chart"),
        ("package", "Helm: Packaging chart"),
    ]
    .into_iter()
    .collect()
});

/// Check helm commands declaratively
pub fn check_helm_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["helm"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if HELM_ALLOW.contains(subcmd.as_str()) || HELM_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = HELM_ASK
        .get(subcmd.as_str())
        .or_else(|| HELM_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("helm: {}", reason)));
    }

    Some(GateResult::ask(format!("helm: {}", subcmd_single)))
}

// === PULUMI (from cloud.toml) ===

pub static PULUMI_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "preview",
        "whoami",
        "version",
        "-h",
        "--help",
        "stack ls",
        "stack list",
        "stack output",
        "stack history",
        "stack export",
        "config get",
    ]
    .into_iter()
    .collect()
});

pub static PULUMI_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("up", "Pulumi: Deploying stack"),
        ("destroy", "Pulumi: Destroying stack"),
        ("refresh", "Pulumi: Refreshing state"),
        ("import", "Pulumi: Importing resource"),
        ("cancel", "Pulumi: Canceling update"),
        ("new", "Pulumi: Creating project"),
        ("stack init", "Pulumi: stack init"),
        ("stack rm", "Pulumi: stack rm"),
        ("stack select", "Pulumi: stack select"),
        ("config set", "Pulumi: config set"),
        ("config rm", "Pulumi: config rm"),
    ]
    .into_iter()
    .collect()
});

/// Check pulumi commands declaratively
pub fn check_pulumi_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pulumi"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if PULUMI_ALLOW.contains(subcmd.as_str()) || PULUMI_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = PULUMI_ASK
        .get(subcmd.as_str())
        .or_else(|| PULUMI_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("pulumi: {}", reason)));
    }

    Some(GateResult::ask(format!("pulumi: {}", subcmd_single)))
}

// === NPM (from package_managers.toml) ===

pub static NPM_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list",
        "ls",
        "ll",
        "la",
        "view",
        "show",
        "info",
        "search",
        "help",
        "get",
        "prefix",
        "root",
        "bin",
        "whoami",
        "token",
        "team",
        "outdated",
        "doctor",
        "explain",
        "why",
        "fund",
        "query",
        "-v",
        "--version",
        "-h",
        "--help",
        "test",
        "build",
        "dev",
        "lint",
        "check",
        "typecheck",
        "format",
        "prettier",
        "eslint",
        "tsc",
    ]
    .into_iter()
    .collect()
});

pub static NPM_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("run", "Running script from package.json"),
        ("run-script", "Running script from package.json"),
        ("start", "Running start script"),
        ("install", "Installing packages"),
        ("i", "Installing packages"),
        ("add", "Installing packages"),
        ("ci", "Clean install"),
        ("uninstall", "Uninstalling packages"),
        ("remove", "Uninstalling packages"),
        ("rm", "Uninstalling packages"),
        ("un", "Uninstalling packages"),
        ("update", "Updating packages"),
        ("up", "Updating packages"),
        ("upgrade", "Updating packages"),
        ("link", "Linking package"),
        ("unlink", "Unlinking package"),
        ("publish", "Publishing package"),
        ("unpublish", "Unpublishing package"),
        ("deprecate", "Deprecating package"),
        ("init", "Initializing package"),
        ("create", "Creating package"),
        ("exec", "Executing package"),
        ("npx", "Executing package"),
        ("prune", "Pruning packages"),
        ("dedupe", "Deduplicating"),
        ("shrinkwrap", "Locking dependencies"),
        ("cache", "Cache operation"),
        ("pack", "Creating tarball"),
        ("set", "Setting config"),
    ]
    .into_iter()
    .collect()
});

/// Check npm commands declaratively
pub fn check_npm_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["npm"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if subcmd_single == "config"
        && cmd
            .args
            .iter()
            .any(|a| ["set", "delete", "edit"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Modifying npm config"));
    }
    if subcmd_single == "audit" && cmd.args.iter().any(|a| ["fix"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Fixing vulnerabilities (modifies dependencies)",
        ));
    }

    if NPM_ALLOW.contains(subcmd.as_str()) || NPM_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "config"
        && !cmd
            .args
            .iter()
            .any(|a| ["set", "delete", "edit"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "audit" && !cmd.args.iter().any(|a| ["fix"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = NPM_ASK
        .get(subcmd.as_str())
        .or_else(|| NPM_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("npm: {}", reason)));
    }

    Some(GateResult::ask(format!("npm: {}", subcmd_single)))
}

// === PNPM (from package_managers.toml) ===

pub static PNPM_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list",
        "ls",
        "ll",
        "why",
        "outdated",
        "-v",
        "--version",
        "-h",
        "--help",
        "test",
        "build",
        "dev",
        "lint",
        "check",
        "typecheck",
        "format",
        "tsc",
    ]
    .into_iter()
    .collect()
});

pub static PNPM_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("run", "Running script from package.json"),
        ("start", "Running start script"),
        ("exec", "Executing arbitrary command"),
        ("install", "Installing packages"),
        ("i", "Installing packages"),
        ("add", "Adding packages"),
        ("remove", "Removing packages"),
        ("rm", "Removing packages"),
        ("uninstall", "Removing packages"),
        ("update", "Updating packages"),
        ("up", "Updating packages"),
        ("link", "Linking package"),
        ("unlink", "Unlinking package"),
        ("publish", "Publishing package"),
        ("init", "Initializing package"),
        ("create", "Creating package"),
        ("dlx", "Executing package"),
        ("prune", "Pruning packages"),
        ("store", "Store operation"),
        ("patch", "Patching package"),
    ]
    .into_iter()
    .collect()
});

/// Check pnpm commands declaratively
pub fn check_pnpm_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pnpm"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if subcmd_single == "audit" && cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Fixing vulnerabilities (modifies dependencies)",
        ));
    }

    if PNPM_ALLOW.contains(subcmd.as_str()) || PNPM_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "audit" && !cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = PNPM_ASK
        .get(subcmd.as_str())
        .or_else(|| PNPM_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("pnpm: {}", reason)));
    }

    Some(GateResult::ask(format!("pnpm: {}", subcmd_single)))
}

// === YARN (from package_managers.toml) ===

pub static YARN_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list",
        "info",
        "why",
        "outdated",
        "audit",
        "-v",
        "--version",
        "-h",
        "--help",
        "test",
        "build",
        "dev",
        "lint",
        "check",
        "typecheck",
        "format",
    ]
    .into_iter()
    .collect()
});

pub static YARN_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("run", "Running script from package.json"),
        ("start", "Running start script"),
        ("exec", "Executing arbitrary command"),
        ("install", "Installing packages"),
        ("add", "Adding packages"),
        ("remove", "Removing packages"),
        ("upgrade", "Upgrading packages"),
        ("upgrade-interactive", "Upgrading packages"),
        ("link", "Linking package"),
        ("unlink", "Unlinking package"),
        ("publish", "Publishing package"),
        ("init", "Initializing package"),
        ("create", "Creating package"),
        ("dlx", "Executing package"),
        ("cache", "Cache operation"),
        ("global", "Global operation"),
        ("set", "Setting config"),
    ]
    .into_iter()
    .collect()
});

/// Check yarn commands declaratively
pub fn check_yarn_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["yarn"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if subcmd_single == "config"
        && cmd
            .args
            .iter()
            .any(|a| ["set", "delete"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Modifying yarn config"));
    }

    if YARN_ALLOW.contains(subcmd.as_str()) || YARN_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "config"
        && !cmd
            .args
            .iter()
            .any(|a| ["set", "delete"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    if let Some(reason) = YARN_ASK
        .get(subcmd.as_str())
        .or_else(|| YARN_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("yarn: {}", reason)));
    }

    Some(GateResult::ask(format!("yarn: {}", subcmd_single)))
}

// === PIP (from package_managers.toml) ===

pub static PIP_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list",
        "show",
        "freeze",
        "check",
        "search",
        "index",
        "debug",
        "-V",
        "--version",
        "-h",
        "--help",
    ]
    .into_iter()
    .collect()
});

pub static PIP_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing packages"),
        ("uninstall", "Uninstalling packages"),
        ("download", "Downloading packages"),
        ("wheel", "Building wheel"),
    ]
    .into_iter()
    .collect()
});

/// Check pip commands declaratively
pub fn check_pip_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pip", "pip3"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Check allow_if_flags (e.g., --dry-run)
    if cmd
        .args
        .iter()
        .any(|a| ["--dry-run", "-n"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if subcmd_single == "config"
        && cmd
            .args
            .iter()
            .any(|a| ["set", "edit", "unset"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Modifying pip config"));
    }
    if subcmd_single == "cache"
        && cmd
            .args
            .iter()
            .any(|a| ["purge", "remove"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Deleting pip cache"));
    }

    if PIP_ALLOW.contains(subcmd.as_str()) || PIP_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "config"
        && !cmd
            .args
            .iter()
            .any(|a| ["set", "edit", "unset"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "cache"
        && !cmd
            .args
            .iter()
            .any(|a| ["purge", "remove"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    if let Some(reason) = PIP_ASK
        .get(subcmd.as_str())
        .or_else(|| PIP_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("pip: {}", reason)));
    }

    Some(GateResult::ask(format!("pip: {}", subcmd_single)))
}

// === UV (from package_managers.toml) ===

pub static UV_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "version",
        "help",
        "tree",
        "--version",
        "-V",
        "-h",
        "--help",
        "pip list",
        "pip show",
        "pip freeze",
        "pip check",
    ]
    .into_iter()
    .collect()
});

pub static UV_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("run", "Running command in environment"),
        ("sync", "Syncing virtual environment"),
        ("lock", "Updating lockfile"),
        ("venv", "Creating virtual environment"),
        ("add", "Adding dependency"),
        ("remove", "Removing dependency"),
        ("tool", "Tool operation"),
        ("python", "Python operation"),
        ("cache", "Cache operation"),
        ("init", "Initializing project"),
        ("build", "Building package"),
        ("publish", "Publishing package"),
        ("pip install", "uv pip: install"),
        ("pip uninstall", "uv pip: uninstall"),
    ]
    .into_iter()
    .collect()
});

/// Check uv commands declaratively
pub fn check_uv_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["uv"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if UV_ALLOW.contains(subcmd.as_str()) || UV_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = UV_ASK
        .get(subcmd.as_str())
        .or_else(|| UV_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("uv: {}", reason)));
    }

    Some(GateResult::ask(format!("uv: {}", subcmd_single)))
}

// === CARGO (from package_managers.toml) ===

pub static CARGO_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "check",
        "doc",
        "tree",
        "metadata",
        "pkgid",
        "verify-project",
        "search",
        "info",
        "locate-project",
        "read-manifest",
        "version",
        "-V",
        "--version",
        "-h",
        "--help",
        "help",
        "build",
        "run",
        "test",
        "bench",
        "fmt",
        "clean",
    ]
    .into_iter()
    .collect()
});

pub static CARGO_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing"),
        ("uninstall", "Uninstalling"),
        ("new", "Creating project"),
        ("init", "Initializing project"),
        ("add", "Adding dependency"),
        ("remove", "Removing dependency"),
        ("update", "Updating dependencies"),
        ("publish", "Publishing crate"),
        ("yank", "Yanking version"),
        ("fix", "Auto-fixing code"),
        ("generate-lockfile", "Generating lockfile"),
    ]
    .into_iter()
    .collect()
});

/// Check cargo commands declaratively
pub fn check_cargo_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["cargo"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if subcmd_single == "clippy" && cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())) {
        return Some(GateResult::ask("Auto-fixing lint suggestions"));
    }

    if CARGO_ALLOW.contains(subcmd.as_str()) || CARGO_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "clippy" && !cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = CARGO_ASK
        .get(subcmd.as_str())
        .or_else(|| CARGO_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("cargo: {}", reason)));
    }

    Some(GateResult::ask(format!("cargo: {}", subcmd_single)))
}

// === RUSTC (from package_managers.toml) ===

/// Check rustc commands declaratively
pub fn check_rustc_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["rustc"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true
        && cmd.args.iter().any(|a| {
            [
                "--version",
                "-V",
                "--print",
                "--explain",
                "--help",
                "-h",
                "-vV",
            ]
            .contains(&a.as_str())
        })
    {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any rustc invocation asks
    Some(GateResult::ask("rustc: Compiling"))
}

// === RUSTUP (from package_managers.toml) ===

pub static RUSTUP_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "show",
        "toolchain list",
        "target list",
        "component list",
        "run",
        "which",
        "doc",
        "--version",
        "-V",
        "--help",
        "-h",
        "help",
    ]
    .into_iter()
    .collect()
});

pub static RUSTUP_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing toolchain"),
        ("update", "Updating toolchains"),
        ("default", "Changing default toolchain"),
        ("toolchain install", "Installing toolchain"),
        ("toolchain uninstall", "Uninstalling toolchain"),
        ("target add", "Adding compilation target"),
        ("target remove", "Removing compilation target"),
        ("component add", "Adding component"),
        ("component remove", "Removing component"),
        ("override", "Setting toolchain override"),
        ("self", "Modifying rustup installation"),
    ]
    .into_iter()
    .collect()
});

/// Check rustup commands declaratively
pub fn check_rustup_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["rustup"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if RUSTUP_ALLOW.contains(subcmd.as_str()) || RUSTUP_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = RUSTUP_ASK
        .get(subcmd.as_str())
        .or_else(|| RUSTUP_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("rustup: {}", reason)));
    }

    Some(GateResult::ask(format!("rustup: {}", subcmd_single)))
}

// === GO (from package_managers.toml) ===

pub static GO_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list",
        "doc",
        "version",
        "vet",
        "help",
        "-h",
        "--help",
        "build",
        "test",
        "clean",
        "mod graph",
        "mod verify",
        "mod why",
    ]
    .into_iter()
    .collect()
});

pub static GO_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("fmt", "Formatting files"),
        ("run", "Executing Go code"),
        ("mod tidy", "Tidying go.mod/go.sum"),
        ("mod download", "Downloading modules"),
        ("install", "Installing"),
        ("get", "Getting packages"),
        ("generate", "Generating code"),
        ("fix", "Fixing code"),
        ("work", "Workspace operation"),
        ("mod init", "go mod: init"),
        ("mod edit", "go mod: edit"),
    ]
    .into_iter()
    .collect()
});

/// Check go commands declaratively
pub fn check_go_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["go"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if subcmd_single == "env" && cmd.args.iter().any(|a| ["-w", "-u"].contains(&a.as_str())) {
        return Some(GateResult::ask("Modifying Go environment config"));
    }

    if GO_ALLOW.contains(subcmd.as_str()) || GO_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "env" && !cmd.args.iter().any(|a| ["-w", "-u"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = GO_ASK
        .get(subcmd.as_str())
        .or_else(|| GO_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("go: {}", reason)));
    }

    Some(GateResult::ask(format!("go: {}", subcmd_single)))
}

// === BUN (from package_managers.toml) ===

pub static BUN_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "pm",
        "-v",
        "--version",
        "-h",
        "--help",
        "test",
        "build",
        "dev",
        "lint",
        "check",
        "typecheck",
        "format",
    ]
    .into_iter()
    .collect()
});

pub static BUN_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("run", "Running script from package.json"),
        ("start", "Running start script"),
        ("install", "Installing packages"),
        ("i", "Installing packages"),
        ("add", "Adding packages"),
        ("remove", "Removing packages"),
        ("rm", "Removing packages"),
        ("update", "Updating packages"),
        ("link", "Linking package"),
        ("unlink", "Unlinking package"),
        ("x", "Executing package"),
        ("init", "Initializing project"),
        ("create", "Creating project"),
        ("publish", "Publishing"),
    ]
    .into_iter()
    .collect()
});

/// Check bun commands declaratively
pub fn check_bun_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["bun"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if BUN_ALLOW.contains(subcmd.as_str()) || BUN_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = BUN_ASK
        .get(subcmd.as_str())
        .or_else(|| BUN_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("bun: {}", reason)));
    }

    Some(GateResult::ask(format!("bun: {}", subcmd_single)))
}

// === CONDA (from package_managers.toml) ===

pub static CONDA_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "info",
        "list",
        "search",
        "package",
        "--version",
        "-V",
        "--help",
        "-h",
        "doctor",
        "notices",
        "compare",
        "env list",
    ]
    .into_iter()
    .collect()
});

pub static CONDA_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing packages"),
        ("remove", "Removing packages"),
        ("uninstall", "Uninstalling packages"),
        ("update", "Updating packages"),
        ("upgrade", "Upgrading packages"),
        ("create", "Creating environment"),
        ("activate", "Activating environment"),
        ("deactivate", "Deactivating environment"),
        ("clean", "Cleaning cache"),
        ("build", "Building package"),
        ("init", "Initializing conda"),
        ("run", "Running in environment"),
        ("env create", "env create"),
        ("env remove", "env remove"),
    ]
    .into_iter()
    .collect()
});

/// Check conda commands declaratively
pub fn check_conda_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["conda", "mamba", "micromamba"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if subcmd_single == "config"
        && cmd.args.iter().any(|a| {
            [
                "--add",
                "--remove",
                "--set",
                "--append",
                "--prepend",
                "--remove-key",
            ]
            .contains(&a.as_str())
        })
    {
        return Some(GateResult::ask("Modifying conda config"));
    }

    if CONDA_ALLOW.contains(subcmd.as_str()) || CONDA_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "config"
        && !cmd.args.iter().any(|a| {
            [
                "--add",
                "--remove",
                "--set",
                "--append",
                "--prepend",
                "--remove-key",
            ]
            .contains(&a.as_str())
        })
    {
        return Some(GateResult::allow());
    }

    if let Some(reason) = CONDA_ASK
        .get(subcmd.as_str())
        .or_else(|| CONDA_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("conda: {}", reason)));
    }

    Some(GateResult::ask(format!("conda: {}", subcmd_single)))
}

// === POETRY (from package_managers.toml) ===

pub static POETRY_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "show",
        "search",
        "check",
        "config list",
        "env info",
        "env list",
        "env activate",
        "version",
        "about",
        "--version",
        "-V",
        "--help",
        "-h",
        "build",
        "lock",
    ]
    .into_iter()
    .collect()
});

pub static POETRY_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("env use", "Creating/activating Python environment"),
        ("env remove", "Removing Python environment"),
        ("run", "Running arbitrary command in environment"),
        ("shell", "Spawning interactive shell"),
        ("install", "Installing dependencies"),
        ("add", "Adding dependency"),
        ("remove", "Removing dependency"),
        ("update", "Updating dependencies"),
        ("init", "Initializing project"),
        ("new", "Creating project"),
        ("publish", "Publishing package"),
        ("cache", "Cache operation"),
        ("export", "Exporting dependencies"),
        ("self", "Self operation"),
        ("source", "Source operation"),
    ]
    .into_iter()
    .collect()
});

/// Check poetry commands declaratively
pub fn check_poetry_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["poetry"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if POETRY_ALLOW.contains(subcmd.as_str()) || POETRY_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "config" && !cmd.args.iter().any(|a| ["--unset"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = POETRY_ASK
        .get(subcmd.as_str())
        .or_else(|| POETRY_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("poetry: {}", reason)));
    }

    Some(GateResult::ask(format!("poetry: {}", subcmd_single)))
}

// === PIPX (from package_managers.toml) ===

pub static PIPX_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    ["list", "environment", "--version", "--help"]
        .into_iter()
        .collect()
});

pub static PIPX_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing application"),
        ("uninstall", "Uninstalling application"),
        ("upgrade", "Upgrading application"),
        ("upgrade-all", "Upgrading all applications"),
        ("reinstall", "Reinstalling application"),
        ("reinstall-all", "Reinstalling all"),
        ("inject", "Injecting package"),
        ("uninject", "Uninjecting package"),
        ("ensurepath", "Modifying PATH"),
        ("run", "Running application"),
    ]
    .into_iter()
    .collect()
});

/// Check pipx commands declaratively
pub fn check_pipx_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pipx"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if PIPX_ALLOW.contains(subcmd.as_str()) || PIPX_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = PIPX_ASK
        .get(subcmd.as_str())
        .or_else(|| PIPX_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("pipx: {}", reason)));
    }

    Some(GateResult::ask(format!("pipx: {}", subcmd_single)))
}

// === MISE (from package_managers.toml) ===

pub static MISE_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "ls",
        "list",
        "current",
        "where",
        "which",
        "env",
        "version",
        "--version",
        "-V",
        "--help",
        "-h",
        "help",
        "doctor",
        "plugins",
        "settings",
        "alias",
        "bin-paths",
        "completion",
        "direnv",
        "outdated",
        "reshim",
        "trust",
        "exec",
        "registry",
    ]
    .into_iter()
    .collect()
});

pub static MISE_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("run", "Running mise task"),
        ("task", "Task operation"),
        ("tasks", "Task operation"),
        ("install", "Installing tool versions"),
        ("i", "Installing tool versions"),
        ("use", "Setting tool version"),
        ("u", "Setting tool version"),
        ("upgrade", "Upgrading tools"),
        ("up", "Upgrading tools"),
        ("uninstall", "Uninstalling tools"),
        ("prune", "Pruning unused versions"),
        ("sync", "Syncing tool versions"),
        ("activate", "Activating mise in shell"),
        ("deactivate", "Deactivating mise"),
        ("implode", "Removing mise installation"),
        ("self-update", "Updating mise itself"),
        ("plugins install", "Installing plugin"),
        ("plugins add", "Installing plugin"),
        ("plugins remove", "Removing plugin"),
        ("plugins update", "Updating plugins"),
        ("cache", "Cache operation"),
        ("link", "Linking tool version"),
    ]
    .into_iter()
    .collect()
});

/// Check mise commands declaratively
pub fn check_mise_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mise"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if MISE_ALLOW.contains(subcmd.as_str()) || MISE_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = MISE_ASK
        .get(subcmd.as_str())
        .or_else(|| MISE_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("mise: {}", reason)));
    }

    Some(GateResult::ask(format!("mise: {}", subcmd_single)))
}

// === BD (from beads.toml) ===

pub static BD_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list",
        "show",
        "ready",
        "blocked",
        "count",
        "search",
        "where",
        "info",
        "version",
        "help",
        "status",
        "doctor",
        "lint",
        "human",
        "onboard",
        "completion",
        "thanks",
        "detect-pollution",
        "dep tree",
        "dep cycles",
        "graph",
        "label list",
        "label list-all",
        "daemons list",
        "daemons health",
        "daemons logs",
        "daemon health",
        "daemon logs",
        "config get",
        "config list",
        "stats",
        "activity",
        "stale",
        "orphans",
        "preflight",
        "epic status",
        "close-eligible",
        "swarm list",
        "gate list",
        "gate show",
        "gate check",
        "gate discover",
        "template list",
        "template show",
        "formula list",
        "formula show",
        "mol show",
        "mol current",
        "mol stale",
        "mol progress",
        "mol list",
        "slot show",
        "slot list",
        "agent show",
        "agent list",
        "state",
        "state list",
        "worktree list",
        "repo list",
        "repo show",
        "jira status",
        "jira list",
        "jira show",
        "linear status",
        "linear list",
        "linear show",
        "ship list",
        "ship show",
        "upgrade status",
        "upgrade review",
        "prime",
        "quickstart",
        "workflow",
        "tips",
        "deleted",
        "hook",
    ]
    .into_iter()
    .collect()
});

pub static BD_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("create", "Creating new issue"),
        ("create-form", "Creating issue via form"),
        ("q", "Quick capturing issue"),
        ("quick", "Quick capturing issue"),
        ("update", "Updating issue"),
        ("edit", "Editing issue in editor"),
        ("close", "Closing issue"),
        ("reopen", "Reopening issue"),
        ("delete", "Deleting issue"),
        ("move", "Moving issue to different rig"),
        ("refile", "Refiling issue"),
        ("set-state", "Setting issue state"),
        ("defer", "Deferring issue"),
        ("undefer", "Undeferring issue"),
        ("dep add", "Adding dependency"),
        ("dep remove", "Removing dependency"),
        ("relate", "Relating issues"),
        ("unrelate", "Unrelating issues"),
        ("duplicate", "Marking as duplicate"),
        ("supersede", "Marking as superseded"),
        ("label add", "Adding label"),
        ("label remove", "Removing label"),
        ("comments add", "Adding comment"),
        ("comment add", "Adding comment"),
        ("sync", "Syncing issues with git"),
        ("export", "Exporting issues"),
        ("import", "Importing issues"),
        ("init", "Initializing beads in project"),
        ("setup", "Setting up integration"),
        ("config set", "Changing configuration"),
        ("config unset", "Unsetting configuration"),
        ("daemons start", "Starting daemon"),
        ("daemons stop", "Stopping daemon"),
        ("daemons restart", "Restarting daemon"),
        ("daemons killall", "Killing all daemons"),
        ("daemon start", "Starting daemon"),
        ("daemon stop", "Stopping daemon"),
        ("daemon restart", "Restarting daemon"),
        ("daemon kill", "Killing daemon"),
        ("daemon run", "Running daemon"),
        ("hooks", "Managing git hooks"),
        ("migrate sync", "Migrating sync"),
        ("migrate issues", "Migrating issues"),
        ("migrate hash-ids", "Migrating hash IDs"),
        ("migrate tombstones", "Migrating tombstones"),
        ("admin", "Admin operation"),
        ("admin cleanup", "Cleaning up issues"),
        ("admin compact", "Compacting issues"),
        ("admin reset", "Resetting database"),
        ("compact", "Compacting old issues"),
        ("cleanup", "Cleaning up issues"),
        ("merge", "Merging issues"),
        ("repair", "Repairing database"),
        ("restore", "Restoring issue"),
        ("upgrade ack", "Acknowledging upgrade"),
        ("epic create", "Creating epic"),
        ("epic close", "Closing epic"),
        ("epic update", "Updating epic"),
        ("swarm create", "Creating swarm"),
        ("swarm close", "Closing swarm"),
        ("swarm update", "Updating swarm"),
        ("swarm add", "Adding to swarm"),
        ("swarm remove", "Removing from swarm"),
        ("gate resolve", "Resolving gate"),
        ("gate add-waiter", "Adding gate waiter"),
        ("template instantiate", "Instantiating template"),
        ("mol burn", "Burning molecule"),
        ("mol squash", "Squashing molecule"),
        ("mol bond", "Bonding molecules"),
        ("mol distill", "Distilling molecule"),
        ("mol create", "Creating molecule"),
        ("pour", "Creating molecule from formula"),
        ("wisp", "Creating ephemeral wisp"),
        ("cook", "Compiling formula to proto"),
        ("formula create", "Creating formula"),
        ("formula delete", "Deleting formula"),
        ("formula update", "Updating formula"),
        ("formula edit", "Editing formula"),
        ("formula convert", "Converting formula"),
        ("slot set", "Setting slot"),
        ("slot clear", "Clearing slot"),
        ("slot claim", "Claiming slot"),
        ("slot release", "Releasing slot"),
        ("agent set", "Setting agent state"),
        ("agent clear", "Clearing agent state"),
        ("agent update", "Updating agent"),
        ("agent create", "Creating agent"),
        ("audit record", "Recording audit entry"),
        ("audit label", "Labeling audit entry"),
        ("ship publish", "Publishing capability"),
        ("ship create", "Creating ship"),
        ("ship delete", "Deleting ship"),
        ("rename-prefix", "Renaming issue prefix"),
        ("worktree add", "Adding worktree"),
        ("worktree remove", "Removing worktree"),
        ("worktree prune", "Pruning worktrees"),
        ("repo add", "Adding repository"),
        ("repo remove", "Removing repository"),
        ("repo set", "Setting repository config"),
        ("repo sync", "Syncing repository"),
        ("jira sync", "Syncing with Jira"),
        ("jira push", "Pushing to Jira"),
        ("jira import", "Importing from Jira"),
        ("jira create", "Creating in Jira"),
        ("linear sync", "Syncing with Linear"),
        ("linear push", "Pushing to Linear"),
        ("linear import", "Importing from Linear"),
        ("linear create", "Creating in Linear"),
        ("mail", "Delegating to mail provider"),
        ("reset", "Resetting database"),
    ]
    .into_iter()
    .collect()
});

/// Check bd commands declaratively
pub fn check_bd_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["bd", "beads"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if subcmd_single == "migrate"
        && cmd
            .args
            .iter()
            .any(|a| ["--apply", "--force"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Migrating database"));
    }
    if subcmd_single == "duplicates"
        && cmd
            .args
            .iter()
            .any(|a| ["--auto-merge"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Auto-merging duplicates"));
    }
    if subcmd_single == "upgrade"
        && cmd
            .args
            .iter()
            .any(|a| ["--apply", "--install"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Applying upgrade"));
    }
    if subcmd_single == "pin"
        && cmd
            .args
            .iter()
            .any(|a| ["--set", "--clear"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Pinning work to agent"));
    }

    if BD_ALLOW.contains(subcmd.as_str()) || BD_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "dep"
        && !cmd
            .args
            .iter()
            .any(|a| ["add", "remove"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "label"
        && !cmd
            .args
            .iter()
            .any(|a| ["add", "remove"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "comments" && !cmd.args.iter().any(|a| ["add"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }
    if subcmd_single == "comment" && !cmd.args.iter().any(|a| ["add"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }
    if subcmd_single == "daemons"
        && !cmd
            .args
            .iter()
            .any(|a| ["start", "stop", "restart", "killall"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "daemon"
        && !cmd
            .args
            .iter()
            .any(|a| ["start", "stop", "restart", "kill", "run"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "config"
        && !cmd
            .args
            .iter()
            .any(|a| ["set", "unset"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "audit"
        && !cmd
            .args
            .iter()
            .any(|a| ["record", "label"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "epic"
        && !cmd
            .args
            .iter()
            .any(|a| ["create", "close", "update"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "swarm"
        && !cmd
            .args
            .iter()
            .any(|a| ["create", "close", "update", "add", "remove"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "gate"
        && !cmd
            .args
            .iter()
            .any(|a| ["resolve", "add-waiter"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "template"
        && !cmd
            .args
            .iter()
            .any(|a| ["instantiate"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "formula"
        && !cmd
            .args
            .iter()
            .any(|a| ["create", "delete", "update", "edit", "convert"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "mol"
        && !cmd
            .args
            .iter()
            .any(|a| ["burn", "squash", "bond", "distill", "create"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "slot"
        && !cmd
            .args
            .iter()
            .any(|a| ["set", "clear", "claim", "release"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "agent"
        && !cmd
            .args
            .iter()
            .any(|a| ["set", "clear", "update", "create"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "worktree"
        && !cmd
            .args
            .iter()
            .any(|a| ["add", "remove", "prune"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "repo"
        && !cmd
            .args
            .iter()
            .any(|a| ["add", "remove", "set", "sync"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "jira"
        && !cmd
            .args
            .iter()
            .any(|a| ["sync", "push", "import", "create"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "linear"
        && !cmd
            .args
            .iter()
            .any(|a| ["sync", "push", "import", "create"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "ship"
        && !cmd
            .args
            .iter()
            .any(|a| ["publish", "create", "delete"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "upgrade"
        && !cmd
            .args
            .iter()
            .any(|a| ["--apply", "--install", "ack"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "migrate"
        && !cmd
            .args
            .iter()
            .any(|a| ["--apply", "--force"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "duplicates"
        && !cmd
            .args
            .iter()
            .any(|a| ["--auto-merge"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "cleanup" && cmd.args.iter().any(|a| ["--dry-run"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }
    if subcmd_single == "compact" && cmd.args.iter().any(|a| ["--dry-run"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }
    if subcmd_single == "delete" && cmd.args.iter().any(|a| ["--dry-run"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }
    if cmd.args.len() >= 2
        && cmd.args[0] == "admin"
        && cmd.args[1] == "cleanup"
        && cmd.args.iter().any(|a| ["--dry-run"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if cmd.args.len() >= 2
        && cmd.args[0] == "admin"
        && cmd.args[1] == "compact"
        && cmd.args.iter().any(|a| ["--dry-run"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "pin"
        && !cmd
            .args
            .iter()
            .any(|a| ["--set", "--clear"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    if let Some(reason) = BD_ASK
        .get(subcmd.as_str())
        .or_else(|| BD_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("bd: {}", reason)));
    }

    Some(GateResult::ask(format!("bd: {}", subcmd_single)))
}

// === TOOL-GATES (from tool_gates.toml) ===

pub static TOOL_GATES_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "pending list",
        "pending count",
        "rules list",
        "hooks status",
    ]
    .into_iter()
    .collect()
});

pub static TOOL_GATES_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("approve", "Adding permanent permission rule"),
        ("rules remove", "Removing permission rule"),
        ("pending clear", "Clearing pending approval queue"),
        ("hooks add", "Installing hooks into Claude Code settings"),
        ("review", "Opening interactive approval TUI"),
    ]
    .into_iter()
    .collect()
});

/// Check tool-gates commands declaratively
pub fn check_tool_gates_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["tool-gates", "bash-gates"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--refresh-tools"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Refreshing tool detection cache"));
    }

    if TOOL_GATES_ALLOW.contains(subcmd.as_str()) || TOOL_GATES_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--help", "-h"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--version", "-V"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--tools-status"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--export-toml", "--gemini-policy"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    if let Some(reason) = TOOL_GATES_ASK
        .get(subcmd.as_str())
        .or_else(|| TOOL_GATES_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("tool-gates: {}", reason)));
    }

    Some(GateResult::ask(format!("tool-gates: {}", subcmd_single)))
}

// === SD (from devtools.toml) ===

/// Check sd commands declaratively
pub fn check_sd_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["sd"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any sd invocation asks
    Some(GateResult::ask("sd: In-place text replacement"))
}

// === SAD (from devtools.toml) ===

/// Check sad commands declaratively
pub fn check_sad_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["sad"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true && cmd.args.iter().any(|a| ["--commit"].contains(&a.as_str())) {
        return Some(GateResult::ask("Applying replacements"));
    }

    Some(GateResult::allow())
}

// === AST-GREP (from devtools.toml) ===

/// Check ast-grep commands declaratively
pub fn check_ast_grep_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["ast-grep", "sg"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-U", "--update-all"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Rewriting code"));
    }

    Some(GateResult::allow())
}

// === YQ (from devtools.toml) ===

/// Check yq commands declaratively
pub fn check_yq_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["yq"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-i", "--inplace"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("In-place YAML edit"));
    }

    Some(GateResult::allow())
}

// === JQ (from devtools.toml) ===

/// Check jq commands declaratively
pub fn check_jq_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["jq"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === SEMGREP (from devtools.toml) ===

/// Check semgrep commands declaratively
pub fn check_semgrep_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["semgrep"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--autofix", "--fix"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Auto-fixing code"));
    }

    Some(GateResult::allow())
}

// === COMBY (from devtools.toml) ===

/// Check comby commands declaratively
pub fn check_comby_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["comby"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-in-place", "-i"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("In-place replacement"));
    }

    Some(GateResult::allow())
}

// === GRIT (from devtools.toml) ===

pub static GRIT_ASK: LazyLock<HashMap<&str, &str>> =
    LazyLock::new(|| [("apply", "Applying migrations")].into_iter().collect());

/// Check grit commands declaratively
pub fn check_grit_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["grit"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if let Some(reason) = GRIT_ASK
        .get(subcmd.as_str())
        .or_else(|| GRIT_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("grit: {}", reason)));
    }

    Some(GateResult::allow())
}

// === WATCHEXEC (from devtools.toml) ===

/// Check watchexec commands declaratively
pub fn check_watchexec_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["watchexec"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any watchexec invocation asks
    Some(GateResult::ask("watchexec: Runs commands on file changes"))
}

// === BIOME (from devtools.toml) ===

pub static BIOME_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| ["lint"].into_iter().collect());

/// Check biome commands declaratively
pub fn check_biome_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["biome"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if subcmd_single == "check"
        && cmd
            .args
            .iter()
            .any(|a| ["--write", "--fix", "--fix-unsafe"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Writing fixes"));
    }
    if subcmd_single == "format" && cmd.args.iter().any(|a| ["--write"].contains(&a.as_str())) {
        return Some(GateResult::ask("Formatting files"));
    }

    if BIOME_ALLOW.contains(subcmd.as_str()) || BIOME_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    Some(GateResult::allow())
}

// === PRETTIER (from devtools.toml) ===

/// Check prettier commands declaratively
pub fn check_prettier_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["prettier"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--write", "-w"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Writing formatted files"));
    }

    Some(GateResult::allow())
}

// === ESLINT (from devtools.toml) ===

/// Check eslint commands declaratively
pub fn check_eslint_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["eslint"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true && cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())) {
        return Some(GateResult::ask("Auto-fixing"));
    }

    Some(GateResult::allow())
}

// === RUFF (from devtools.toml) ===

pub static RUFF_ASK: LazyLock<HashMap<&str, &str>> =
    LazyLock::new(|| [("format", "Formatting files")].into_iter().collect());

/// Check ruff commands declaratively
pub fn check_ruff_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["ruff"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if subcmd_single == "check" && cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())) {
        return Some(GateResult::ask("Auto-fixing"));
    }

    // Check conditional allow rules
    if subcmd_single == "format"
        && cmd
            .args
            .iter()
            .any(|a| ["--check", "--diff"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    if let Some(reason) = RUFF_ASK
        .get(subcmd.as_str())
        .or_else(|| RUFF_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("ruff: {}", reason)));
    }

    Some(GateResult::allow())
}

// === BLACK (from devtools.toml) ===

/// Check black commands declaratively
pub fn check_black_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["black"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--check", "--diff"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any black invocation asks
    Some(GateResult::ask("black: Formatting files"))
}

// === ISORT (from devtools.toml) ===

/// Check isort commands declaratively
pub fn check_isort_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["isort"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--check", "--check-only", "--diff"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any isort invocation asks
    Some(GateResult::ask("isort: Sorting imports"))
}

// === SHELLCHECK (from devtools.toml) ===

/// Check shellcheck commands declaratively
pub fn check_shellcheck_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["shellcheck"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === HADOLINT (from devtools.toml) ===

/// Check hadolint commands declaratively
pub fn check_hadolint_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["hadolint"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === GOLANGCI-LINT (from devtools.toml) ===

/// Check golangci-lint commands declaratively
pub fn check_golangci_lint_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["golangci-lint"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true && cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())) {
        return Some(GateResult::ask("Applying lint fixes"));
    }

    Some(GateResult::allow())
}

// === GCI (from devtools.toml) ===

/// Check gci commands declaratively
pub fn check_gci_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["gci"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true && cmd.args.iter().any(|a| ["write"].contains(&a.as_str())) {
        return Some(GateResult::ask("Formatting imports"));
    }

    Some(GateResult::allow())
}

// === AIR (from devtools.toml) ===

/// Check air commands declaratively
pub fn check_air_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["air"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === ACTIONLINT (from devtools.toml) ===

/// Check actionlint commands declaratively
pub fn check_actionlint_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["actionlint"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === GITLEAKS (from devtools.toml) ===

/// Check gitleaks commands declaratively
pub fn check_gitleaks_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["gitleaks"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === LEFTHOOK (from devtools.toml) ===

pub static LEFTHOOK_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["run", "version", "dump"].into_iter().collect());

pub static LEFTHOOK_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing git hooks"),
        ("uninstall", "Removing git hooks"),
        ("add", "Adding hook configuration"),
    ]
    .into_iter()
    .collect()
});

/// Check lefthook commands declaratively
pub fn check_lefthook_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["lefthook"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if LEFTHOOK_ALLOW.contains(subcmd.as_str()) || LEFTHOOK_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = LEFTHOOK_ASK
        .get(subcmd.as_str())
        .or_else(|| LEFTHOOK_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("lefthook: {}", reason)));
    }

    Some(GateResult::ask(format!("lefthook: {}", subcmd_single)))
}

// === VITE (from devtools.toml) ===

/// Check vite commands declaratively
pub fn check_vite_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["vite"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === VITEST (from devtools.toml) ===

/// Check vitest commands declaratively
pub fn check_vitest_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["vitest"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === JEST (from devtools.toml) ===

/// Check jest commands declaratively
pub fn check_jest_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["jest"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === MOCHA (from devtools.toml) ===

/// Check mocha commands declaratively
pub fn check_mocha_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mocha"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === TSC (from devtools.toml) ===

/// Check tsc commands declaratively
pub fn check_tsc_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["tsc"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === TSUP (from devtools.toml) ===

/// Check tsup commands declaratively
pub fn check_tsup_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["tsup"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === ESBUILD (from devtools.toml) ===

/// Check esbuild commands declaratively
pub fn check_esbuild_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["esbuild"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === TURBO (from devtools.toml) ===

/// Check turbo commands declaratively
pub fn check_turbo_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["turbo"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === NX (from devtools.toml) ===

/// Check nx commands declaratively
pub fn check_nx_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["nx"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === KNIP (from devtools.toml) ===

/// Check knip commands declaratively
pub fn check_knip_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["knip"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === OXLINT (from devtools.toml) ===

/// Check oxlint commands declaratively
pub fn check_oxlint_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["oxlint"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === GOFMT (from devtools.toml) ===

/// Check gofmt commands declaratively
pub fn check_gofmt_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["gofmt"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true && cmd.args.iter().any(|a| ["-w"].contains(&a.as_str())) {
        return Some(GateResult::ask("Formatting files"));
    }

    Some(GateResult::allow())
}

// === GOIMPORTS (from devtools.toml) ===

/// Check goimports commands declaratively
pub fn check_goimports_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["goimports"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true && cmd.args.iter().any(|a| ["-w"].contains(&a.as_str())) {
        return Some(GateResult::ask("Formatting imports"));
    }

    Some(GateResult::allow())
}

// === SHFMT (from devtools.toml) ===

/// Check shfmt commands declaratively
pub fn check_shfmt_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["shfmt"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true && cmd.args.iter().any(|a| ["-w"].contains(&a.as_str())) {
        return Some(GateResult::ask("Formatting files"));
    }

    Some(GateResult::allow())
}

// === RUSTFMT (from devtools.toml) ===

/// Check rustfmt commands declaratively
pub fn check_rustfmt_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["rustfmt"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true && cmd.args.iter().any(|a| ["--check"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any rustfmt invocation asks
    Some(GateResult::ask("rustfmt: Formatting files"))
}

// === STYLUA (from devtools.toml) ===

/// Check stylua commands declaratively
pub fn check_stylua_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["stylua"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true && cmd.args.iter().any(|a| ["--check"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any stylua invocation asks
    Some(GateResult::ask("stylua: Formatting files"))
}

// === CLANG-FORMAT (from devtools.toml) ===

/// Check clang-format commands declaratively
pub fn check_clang_format_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["clang-format"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true && cmd.args.iter().any(|a| ["-i"].contains(&a.as_str())) {
        return Some(GateResult::ask("Formatting files in-place"));
    }

    Some(GateResult::allow())
}

// === AUTOPEP8 (from devtools.toml) ===

/// Check autopep8 commands declaratively
pub fn check_autopep8_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["autopep8"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-i", "--in-place"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Formatting files in-place"));
    }

    Some(GateResult::allow())
}

// === RUBOCOP (from devtools.toml) ===

/// Check rubocop commands declaratively
pub fn check_rubocop_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["rubocop"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-a", "-A", "--auto-correct", "--autocorrect"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Auto-correcting"));
    }

    Some(GateResult::allow())
}

// === STANDARDRB (from devtools.toml) ===

/// Check standardrb commands declaratively
pub fn check_standardrb_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["standardrb"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-a", "-A", "--auto-correct", "--autocorrect"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Auto-correcting"));
    }

    Some(GateResult::allow())
}

// === PATCH (from devtools.toml) ===

/// Check patch commands declaratively
pub fn check_patch_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["patch"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true && cmd.args.iter().any(|a| ["--dry-run"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any patch invocation asks
    Some(GateResult::ask(
        "patch: Applying patch (targets come from patch file content, not CLI args)",
    ))
}

// === DOS2UNIX (from devtools.toml) ===

/// Check dos2unix commands declaratively
pub fn check_dos2unix_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["dos2unix"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any dos2unix invocation asks
    Some(GateResult::ask("dos2unix: Converting line endings"))
}

// === UNIX2DOS (from devtools.toml) ===

/// Check unix2dos commands declaratively
pub fn check_unix2dos_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["unix2dos"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any unix2dos invocation asks
    Some(GateResult::ask("unix2dos: Converting line endings"))
}

// === STYLELINT (from devtools.toml) ===

/// Check stylelint commands declaratively
pub fn check_stylelint_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["stylelint"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true && cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())) {
        return Some(GateResult::ask("Auto-fixing styles"));
    }

    Some(GateResult::allow())
}

// === MIX (from devtools.toml) ===

pub static MIX_ASK: LazyLock<HashMap<&str, &str>> =
    LazyLock::new(|| [("format", "Formatting files")].into_iter().collect());

/// Check mix commands declaratively
pub fn check_mix_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mix"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if let Some(reason) = MIX_ASK
        .get(subcmd.as_str())
        .or_else(|| MIX_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("mix: {}", reason)));
    }

    Some(GateResult::ask(format!("mix: {}", subcmd_single)))
}

// === PERLTIDY (from devtools.toml) ===

/// Check perltidy commands declaratively
pub fn check_perltidy_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["perltidy"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true && cmd.args.iter().any(|a| ["-b"].contains(&a.as_str())) {
        return Some(GateResult::ask("Formatting in-place"));
    }

    Some(GateResult::allow())
}

// === DARTFMT (from devtools.toml) ===

/// Check dartfmt commands declaratively
pub fn check_dartfmt_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["dartfmt"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any dartfmt invocation asks
    Some(GateResult::ask("dartfmt: Formatting files"))
}

// === DART (from devtools.toml) ===

pub static DART_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["analyze", "info", "--version"].into_iter().collect());

pub static DART_ASK: LazyLock<HashMap<&str, &str>> =
    LazyLock::new(|| [("format", "Formatting files")].into_iter().collect());

/// Check dart commands declaratively
pub fn check_dart_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["dart"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if DART_ALLOW.contains(subcmd.as_str()) || DART_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = DART_ASK
        .get(subcmd.as_str())
        .or_else(|| DART_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("dart: {}", reason)));
    }

    Some(GateResult::ask(format!("dart: {}", subcmd_single)))
}

// === ELM-FORMAT (from devtools.toml) ===

/// Check elm-format commands declaratively
pub fn check_elm_format_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["elm-format"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any elm-format invocation asks
    Some(GateResult::ask("elm-format: Formatting files"))
}

// === SCALAFMT (from devtools.toml) ===

/// Check scalafmt commands declaratively
pub fn check_scalafmt_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["scalafmt"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true && cmd.args.iter().any(|a| ["--check"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any scalafmt invocation asks
    Some(GateResult::ask("scalafmt: Formatting files"))
}

// === KTLINT (from devtools.toml) ===

/// Check ktlint commands declaratively
pub fn check_ktlint_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["ktlint"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-F", "--format"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Formatting files"));
    }

    Some(GateResult::allow())
}

// === SWIFTFORMAT (from devtools.toml) ===

/// Check swiftformat commands declaratively
pub fn check_swiftformat_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["swiftformat"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true && cmd.args.iter().any(|a| ["--lint"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any swiftformat invocation asks
    Some(GateResult::ask("swiftformat: Formatting files"))
}

// === BUF (from devtools.toml) ===

pub static BUF_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    ["lint", "breaking", "ls-files", "--version"]
        .into_iter()
        .collect()
});

pub static BUF_ASK: LazyLock<HashMap<&str, &str>> =
    LazyLock::new(|| [("format", "Formatting files")].into_iter().collect());

/// Check buf commands declaratively
pub fn check_buf_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["buf"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if BUF_ALLOW.contains(subcmd.as_str()) || BUF_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = BUF_ASK
        .get(subcmd.as_str())
        .or_else(|| BUF_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("buf: {}", reason)));
    }

    Some(GateResult::ask(format!("buf: {}", subcmd_single)))
}

// === RM (from filesystem.toml) ===

pub static RM_BLOCK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("-rf /", "rm -rf / blocked"),
        ("-rf /*", "rm -rf /* blocked"),
        ("-rf ~", "rm -rf ~ blocked"),
        ("-fr /", "rm -fr / blocked"),
        ("-fr ~", "rm -fr ~ blocked"),
    ]
    .into_iter()
    .collect()
});

/// Check rm commands declaratively
pub fn check_rm_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["rm"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if let Some(reason) = RM_BLOCK.get(subcmd.as_str()) {
        return Some(GateResult::block(format!("rm: {}", reason)));
    }

    // Check conditional block rules

    Some(GateResult::ask(format!("rm: {}", subcmd_single)))
}

// === MV (from filesystem.toml) ===

/// Check mv commands declaratively
pub fn check_mv_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mv"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any mv invocation asks
    Some(GateResult::ask("mv: Moving files"))
}

// === CP (from filesystem.toml) ===

/// Check cp commands declaratively
pub fn check_cp_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["cp"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any cp invocation asks
    Some(GateResult::ask("cp: Copying files"))
}

// === MKDIR (from filesystem.toml) ===

/// Check mkdir commands declaratively
pub fn check_mkdir_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mkdir"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any mkdir invocation asks
    Some(GateResult::ask("mkdir: Creating directory"))
}

// === RMDIR (from filesystem.toml) ===

/// Check rmdir commands declaratively
pub fn check_rmdir_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["rmdir"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any rmdir invocation asks
    Some(GateResult::ask("rmdir: Removing directory (if empty)"))
}

// === TOUCH (from filesystem.toml) ===

/// Check touch commands declaratively
pub fn check_touch_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["touch"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any touch invocation asks
    Some(GateResult::ask("touch: Creating/updating file"))
}

// === CHMOD (from filesystem.toml) ===

/// Check chmod commands declaratively
pub fn check_chmod_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["chmod"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any chmod invocation asks
    Some(GateResult::ask("chmod: Changing permissions"))
}

// === CHOWN (from filesystem.toml) ===

/// Check chown commands declaratively
pub fn check_chown_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["chown"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any chown invocation asks
    Some(GateResult::ask("chown: Changing permissions"))
}

// === CHGRP (from filesystem.toml) ===

/// Check chgrp commands declaratively
pub fn check_chgrp_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["chgrp"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any chgrp invocation asks
    Some(GateResult::ask("chgrp: Changing permissions"))
}

// === LN (from filesystem.toml) ===

/// Check ln commands declaratively
pub fn check_ln_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["ln"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any ln invocation asks
    Some(GateResult::ask("ln: Creating link"))
}

// === PERL (from filesystem.toml) ===

/// Check perl commands declaratively
pub fn check_perl_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["perl"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any perl invocation asks
    Some(GateResult::ask("perl: perl: can execute arbitrary code"))
}

// === TAR (from filesystem.toml) ===

pub static TAR_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["-t", "--list"].into_iter().collect());

/// Check tar commands declaratively
pub fn check_tar_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["tar"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if TAR_ALLOW.contains(subcmd.as_str()) || TAR_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("tar: {}", subcmd_single)))
}

// === UNZIP (from filesystem.toml) ===

/// Check unzip commands declaratively
pub fn check_unzip_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["unzip"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true && cmd.args.iter().any(|a| ["-l"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any unzip invocation asks
    Some(GateResult::ask("unzip: Extracting archive"))
}

// === ZIP (from filesystem.toml) ===

/// Check zip commands declaratively
pub fn check_zip_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["zip"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any zip invocation asks
    Some(GateResult::ask("zip: Creating/modifying archive"))
}

// === CURL (from network.toml) ===

pub static CURL_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "-h", "--help"].into_iter().collect());

/// Check curl commands declaratively
pub fn check_curl_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["curl"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if CURL_ALLOW.contains(subcmd.as_str()) || CURL_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-I", "--head"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    Some(GateResult::allow())
}

// === WGET (from network.toml) ===

pub static WGET_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "-h", "--help"].into_iter().collect());

/// Check wget commands declaratively
pub fn check_wget_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["wget"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-O", "--output-document", "-P", "--directory-prefix"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Downloading file"));
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-r", "--recursive"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Recursive download"));
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-m", "--mirror"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Mirroring site"));
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--post-data", "--post-file"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("POST request"));
    }

    if WGET_ALLOW.contains(subcmd.as_str()) || WGET_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if true && cmd.args.iter().any(|a| ["--spider"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any wget invocation asks
    Some(GateResult::ask("wget: Downloading"))
}

// === SSH (from network.toml) ===

/// Check ssh commands declaratively
pub fn check_ssh_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["ssh"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any ssh invocation asks
    Some(GateResult::ask("ssh: Remote connection"))
}

// === SCP (from network.toml) ===

/// Check scp commands declaratively
pub fn check_scp_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["scp"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any scp invocation asks
    Some(GateResult::ask("scp: File transfer"))
}

// === SFTP (from network.toml) ===

/// Check sftp commands declaratively
pub fn check_sftp_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["sftp"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any sftp invocation asks
    Some(GateResult::ask("sftp: File transfer"))
}

// === RSYNC (from network.toml) ===

/// Check rsync commands declaratively
pub fn check_rsync_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["rsync"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Check allow_if_flags (e.g., --dry-run)
    if cmd
        .args
        .iter()
        .any(|a| ["-n", "--dry-run"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any rsync invocation asks
    Some(GateResult::ask("rsync: File sync"))
}

// === NC (from network.toml) ===

/// Check nc commands declaratively
pub fn check_nc_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["nc", "ncat", "netcat"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional block rules

    // Check ask rules with flag/prefix conditions
    if true && cmd.args.iter().any(|a| ["-l"].contains(&a.as_str())) {
        return Some(GateResult::ask("Listen mode (opens port)"));
    }

    // Bare ask rule - any nc invocation asks
    Some(GateResult::ask("nc: Network connection"))
}

// === HTTP (from network.toml) ===

pub static HTTP_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "--help", "GET"].into_iter().collect());

pub static HTTP_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("POST", "HTTPie: POST request"),
        ("PUT", "HTTPie: PUT request"),
        ("DELETE", "HTTPie: DELETE request"),
        ("PATCH", "HTTPie: PATCH request"),
    ]
    .into_iter()
    .collect()
});

/// Check http commands declaratively
pub fn check_http_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["http", "https", "xh"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if HTTP_ALLOW.contains(subcmd.as_str()) || HTTP_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = HTTP_ASK
        .get(subcmd.as_str())
        .or_else(|| HTTP_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("http: {}", reason)));
    }

    Some(GateResult::ask(format!("http: {}", subcmd_single)))
}

// === SHUTDOWN (from system.toml) ===

/// Check shutdown commands declaratively
pub fn check_shutdown_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["shutdown"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any shutdown invocation is blocked
    Some(GateResult::block("shutdown: System power command blocked"))
}

// === REBOOT (from system.toml) ===

/// Check reboot commands declaratively
pub fn check_reboot_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["reboot"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any reboot invocation is blocked
    Some(GateResult::block("reboot: System power command blocked"))
}

// === POWEROFF (from system.toml) ===

/// Check poweroff commands declaratively
pub fn check_poweroff_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["poweroff"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any poweroff invocation is blocked
    Some(GateResult::block("poweroff: System power command blocked"))
}

// === HALT (from system.toml) ===

/// Check halt commands declaratively
pub fn check_halt_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["halt"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any halt invocation is blocked
    Some(GateResult::block("halt: System power command blocked"))
}

// === INIT (from system.toml) ===

/// Check init commands declaratively
pub fn check_init_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["init"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any init invocation is blocked
    Some(GateResult::block("init: System power command blocked"))
}

// === MKFS (from system.toml) ===

/// Check mkfs commands declaratively
pub fn check_mkfs_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mkfs"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any mkfs invocation is blocked
    Some(GateResult::block("mkfs: Disk partitioning blocked"))
}

// === FDISK (from system.toml) ===

/// Check fdisk commands declaratively
pub fn check_fdisk_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["fdisk"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any fdisk invocation is blocked
    Some(GateResult::block("fdisk: Disk partitioning blocked"))
}

// === PARTED (from system.toml) ===

/// Check parted commands declaratively
pub fn check_parted_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["parted"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any parted invocation is blocked
    Some(GateResult::block("parted: Disk partitioning blocked"))
}

// === GDISK (from system.toml) ===

/// Check gdisk commands declaratively
pub fn check_gdisk_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["gdisk"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any gdisk invocation is blocked
    Some(GateResult::block("gdisk: Disk partitioning blocked"))
}

// === DD (from system.toml) ===

/// Check dd commands declaratively
pub fn check_dd_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["dd"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any dd invocation is blocked
    Some(GateResult::block("dd: Low-level disk operation blocked"))
}

// === SHRED (from system.toml) ===

/// Check shred commands declaratively
pub fn check_shred_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["shred"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any shred invocation is blocked
    Some(GateResult::block("shred: Secure delete blocked"))
}

// === WIPE (from system.toml) ===

/// Check wipe commands declaratively
pub fn check_wipe_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["wipe"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any wipe invocation is blocked
    Some(GateResult::block("wipe: Secure wipe blocked"))
}

// === MKE2FS (from system.toml) ===

/// Check mke2fs commands declaratively
pub fn check_mke2fs_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mke2fs"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any mke2fs invocation is blocked
    Some(GateResult::block("mke2fs: Filesystem creation blocked"))
}

// === MKSWAP (from system.toml) ===

/// Check mkswap commands declaratively
pub fn check_mkswap_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mkswap"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any mkswap invocation is blocked
    Some(GateResult::block("mkswap: Swap creation blocked"))
}

// === WIPEFS (from system.toml) ===

/// Check wipefs commands declaratively
pub fn check_wipefs_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["wipefs"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any wipefs invocation is blocked
    Some(GateResult::block("wipefs: Filesystem wipe blocked"))
}

// === HDPARM (from system.toml) ===

/// Check hdparm commands declaratively
pub fn check_hdparm_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["hdparm"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any hdparm invocation is blocked
    Some(GateResult::block("hdparm: Disk parameters blocked"))
}

// === INSMOD (from system.toml) ===

/// Check insmod commands declaratively
pub fn check_insmod_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["insmod"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any insmod invocation is blocked
    Some(GateResult::block("insmod: Kernel module loading blocked"))
}

// === RMMOD (from system.toml) ===

/// Check rmmod commands declaratively
pub fn check_rmmod_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["rmmod"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any rmmod invocation is blocked
    Some(GateResult::block("rmmod: Kernel module removal blocked"))
}

// === MODPROBE (from system.toml) ===

/// Check modprobe commands declaratively
pub fn check_modprobe_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["modprobe"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any modprobe invocation is blocked
    Some(GateResult::block("modprobe: Kernel module loading blocked"))
}

// === GRUB-INSTALL (from system.toml) ===

/// Check grub-install commands declaratively
pub fn check_grub_install_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["grub-install"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any grub-install invocation is blocked
    Some(GateResult::block(
        "grub-install: Bootloader modification blocked",
    ))
}

// === UPDATE-GRUB (from system.toml) ===

/// Check update-grub commands declaratively
pub fn check_update_grub_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["update-grub"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any update-grub invocation is blocked
    Some(GateResult::block(
        "update-grub: Bootloader modification blocked",
    ))
}

// === USERADD (from system.toml) ===

/// Check useradd commands declaratively
pub fn check_useradd_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["useradd"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any useradd invocation is blocked
    Some(GateResult::block("useradd: User management blocked"))
}

// === USERDEL (from system.toml) ===

/// Check userdel commands declaratively
pub fn check_userdel_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["userdel"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any userdel invocation is blocked
    Some(GateResult::block("userdel: User management blocked"))
}

// === USERMOD (from system.toml) ===

/// Check usermod commands declaratively
pub fn check_usermod_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["usermod"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any usermod invocation is blocked
    Some(GateResult::block("usermod: User management blocked"))
}

// === PASSWD (from system.toml) ===

/// Check passwd commands declaratively
pub fn check_passwd_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["passwd"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any passwd invocation is blocked
    Some(GateResult::block("passwd: Password change blocked"))
}

// === CHSH (from system.toml) ===

/// Check chsh commands declaratively
pub fn check_chsh_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["chsh"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any chsh invocation is blocked
    Some(GateResult::block("chsh: Shell change blocked"))
}

// === IPTABLES (from system.toml) ===

/// Check iptables commands declaratively
pub fn check_iptables_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["iptables"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any iptables invocation is blocked
    Some(GateResult::block("iptables: Firewall modification blocked"))
}

// === UFW (from system.toml) ===

/// Check ufw commands declaratively
pub fn check_ufw_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["ufw"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any ufw invocation is blocked
    Some(GateResult::block("ufw: Firewall modification blocked"))
}

// === FIREWALL-CMD (from system.toml) ===

/// Check firewall-cmd commands declaratively
pub fn check_firewall_cmd_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["firewall-cmd"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any firewall-cmd invocation is blocked
    Some(GateResult::block(
        "firewall-cmd: Firewall modification blocked",
    ))
}

// === CHATTR (from system.toml) ===

/// Check chattr commands declaratively
pub fn check_chattr_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["chattr"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any chattr invocation is blocked
    Some(GateResult::block("chattr: File attribute change blocked"))
}

// === MOUNT (from system.toml) ===

/// Check mount commands declaratively
pub fn check_mount_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mount"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--version", "--help", "-h", "-V"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any mount invocation asks
    Some(GateResult::ask("mount: Mounting filesystem"))
}

// === UMOUNT (from system.toml) ===

/// Check umount commands declaratively
pub fn check_umount_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["umount"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any umount invocation is blocked
    Some(GateResult::block("umount: Unmounting blocked"))
}

// === SWAPOFF (from system.toml) ===

/// Check swapoff commands declaratively
pub fn check_swapoff_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["swapoff"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any swapoff invocation is blocked
    Some(GateResult::block("swapoff: Swap management blocked"))
}

// === SWAPON (from system.toml) ===

/// Check swapon commands declaratively
pub fn check_swapon_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["swapon"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any swapon invocation is blocked
    Some(GateResult::block("swapon: Swap management blocked"))
}

// === LVREMOVE (from system.toml) ===

/// Check lvremove commands declaratively
pub fn check_lvremove_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["lvremove"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any lvremove invocation is blocked
    Some(GateResult::block("lvremove: LVM management blocked"))
}

// === VGREMOVE (from system.toml) ===

/// Check vgremove commands declaratively
pub fn check_vgremove_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["vgremove"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any vgremove invocation is blocked
    Some(GateResult::block("vgremove: LVM management blocked"))
}

// === PVREMOVE (from system.toml) ===

/// Check pvremove commands declaratively
pub fn check_pvremove_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pvremove"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any pvremove invocation is blocked
    Some(GateResult::block("pvremove: LVM management blocked"))
}

// === PSQL (from system.toml) ===

/// Check psql commands declaratively
pub fn check_psql_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["psql"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-l", "--list"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("psql: {}", subcmd_single)))
}

// === CREATEDB (from system.toml) ===

/// Check createdb commands declaratively
pub fn check_createdb_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["createdb"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any createdb invocation asks
    Some(GateResult::ask("createdb: Creating database"))
}

// === DROPDB (from system.toml) ===

/// Check dropdb commands declaratively
pub fn check_dropdb_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["dropdb"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any dropdb invocation asks
    Some(GateResult::ask("dropdb: Dropping database"))
}

// === PG_DUMP (from system.toml) ===

/// Check pg_dump commands declaratively
pub fn check_pg_dump_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pg_dump"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === PG_RESTORE (from system.toml) ===

/// Check pg_restore commands declaratively
pub fn check_pg_restore_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pg_restore"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any pg_restore invocation asks
    Some(GateResult::ask("pg_restore: Restoring database"))
}

// === MIGRATE (from system.toml) ===

/// Check migrate commands declaratively
pub fn check_migrate_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["migrate"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any migrate invocation asks
    Some(GateResult::ask("migrate: Running database migration"))
}

// === GOOSE (from system.toml) ===

/// Check goose commands declaratively
pub fn check_goose_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["goose"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any goose invocation asks
    Some(GateResult::ask("goose: Running database migration"))
}

// === DBMATE (from system.toml) ===

/// Check dbmate commands declaratively
pub fn check_dbmate_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["dbmate"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any dbmate invocation asks
    Some(GateResult::ask("dbmate: Running database migration"))
}

// === FLYWAY (from system.toml) ===

/// Check flyway commands declaratively
pub fn check_flyway_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["flyway"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any flyway invocation asks
    Some(GateResult::ask("flyway: Running database migration"))
}

// === ALEMBIC (from system.toml) ===

pub static ALEMBIC_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    ["history", "current", "heads", "branches", "show"]
        .into_iter()
        .collect()
});

pub static ALEMBIC_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("upgrade", "Running database migration"),
        ("downgrade", "Rolling back database migration"),
        ("revision", "Creating new migration"),
        ("stamp", "Stamping database version"),
    ]
    .into_iter()
    .collect()
});

/// Check alembic commands declaratively
pub fn check_alembic_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["alembic"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if ALEMBIC_ALLOW.contains(subcmd.as_str()) || ALEMBIC_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = ALEMBIC_ASK
        .get(subcmd.as_str())
        .or_else(|| ALEMBIC_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("alembic: {}", reason)));
    }

    Some(GateResult::ask(format!("alembic: {}", subcmd_single)))
}

// === MYSQL (from system.toml) ===

/// Check mysql commands declaratively
pub fn check_mysql_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mysql"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::ask(format!("mysql: {}", subcmd_single)))
}

// === SQLITE3 (from system.toml) ===

/// Check sqlite3 commands declaratively
pub fn check_sqlite3_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["sqlite3"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true && cmd.args.iter().any(|a| ["-readonly"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any sqlite3 invocation asks
    Some(GateResult::ask("sqlite3: Database access"))
}

// === MONGOSH (from system.toml) ===

/// Check mongosh commands declaratively
pub fn check_mongosh_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mongosh", "mongo"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if true && cmd.args.iter().any(|a| ["--eval"].contains(&a.as_str())) {
        return Some(GateResult::ask("Database session"));
    }

    // Bare ask rule - any mongosh invocation asks
    Some(GateResult::ask("mongosh: Database session"))
}

// === REDIS-CLI (from system.toml) ===

/// Check redis-cli commands declaratively
pub fn check_redis_cli_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["redis-cli"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::ask(format!("redis-cli: {}", subcmd_single)))
}

// === KILL (from system.toml) ===

/// Check kill commands declaratively
pub fn check_kill_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["kill"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true && cmd.args.iter().any(|a| ["-0"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any kill invocation asks
    Some(GateResult::ask("kill: Terminating process(es)"))
}

// === PKILL (from system.toml) ===

/// Check pkill commands declaratively
pub fn check_pkill_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pkill"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any pkill invocation asks
    Some(GateResult::ask("pkill: Terminating process(es)"))
}

// === KILLALL (from system.toml) ===

/// Check killall commands declaratively
pub fn check_killall_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["killall"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any killall invocation asks
    Some(GateResult::ask("killall: Terminating process(es)"))
}

// === XKILL (from system.toml) ===

/// Check xkill commands declaratively
pub fn check_xkill_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["xkill"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any xkill invocation asks
    Some(GateResult::ask("xkill: Terminating process(es)"))
}

// === MAKE (from system.toml) ===

pub static MAKE_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "test",
        "tests",
        "check",
        "lint",
        "build",
        "all",
        "clean",
        "format",
        "fmt",
        "typecheck",
        "dev",
        "run",
        "help",
    ]
    .into_iter()
    .collect()
});

/// Check make commands declaratively
pub fn check_make_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["make"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Check allow_if_flags (e.g., --dry-run)
    if cmd
        .args
        .iter()
        .any(|a| ["-n", "--dry-run", "--just-print", "--recon"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if cmd
        .args
        .iter()
        .any(|a| ["-p", "--print-data-base", "-q", "--question"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if MAKE_ALLOW.contains(subcmd.as_str()) || MAKE_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("make: {}", subcmd_single)))
}

// === CMAKE (from system.toml) ===

pub static CMAKE_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "--help"].into_iter().collect());

/// Check cmake commands declaratively
pub fn check_cmake_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["cmake"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Check allow_if_flags (e.g., --dry-run)
    if cmd
        .args
        .iter()
        .any(|a| ["-N", "--view-only"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if CMAKE_ALLOW.contains(subcmd.as_str()) || CMAKE_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any cmake invocation asks
    Some(GateResult::ask("cmake: Configuring build"))
}

// === NINJA (from system.toml) ===

pub static NINJA_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| ["-t"].into_iter().collect());

pub static NINJA_ASK: LazyLock<HashMap<&str, &str>> =
    LazyLock::new(|| [("clean", "Cleaning build")].into_iter().collect());

/// Check ninja commands declaratively
pub fn check_ninja_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["ninja"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if NINJA_ALLOW.contains(subcmd.as_str()) || NINJA_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = NINJA_ASK
        .get(subcmd.as_str())
        .or_else(|| NINJA_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("ninja: {}", reason)));
    }

    Some(GateResult::ask(format!("ninja: {}", subcmd_single)))
}

// === JUST (from system.toml) ===

pub static JUST_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    ["--list", "--summary", "--dump", "--evaluate"]
        .into_iter()
        .collect()
});

/// Check just commands declaratively
pub fn check_just_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["just"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if JUST_ALLOW.contains(subcmd.as_str()) || JUST_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("just: {}", subcmd_single)))
}

// === TASK (from system.toml) ===

pub static TASK_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--list", "--list-all"].into_iter().collect());

/// Check task commands declaratively
pub fn check_task_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["task"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if TASK_ALLOW.contains(subcmd.as_str()) || TASK_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("task: {}", subcmd_single)))
}

// === GRADLE (from system.toml) ===

pub static GRADLE_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "tasks",
        "help",
        "dependencies",
        "properties",
        "build",
        "test",
        "check",
        "clean",
    ]
    .into_iter()
    .collect()
});

pub static GRADLE_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("publish", "Publishing artifacts"),
        ("uploadArchives", "Uploading archives"),
    ]
    .into_iter()
    .collect()
});

/// Check gradle commands declaratively
pub fn check_gradle_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["gradle", "gradlew", "./gradlew"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if GRADLE_ALLOW.contains(subcmd.as_str()) || GRADLE_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = GRADLE_ASK
        .get(subcmd.as_str())
        .or_else(|| GRADLE_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("gradle: {}", reason)));
    }

    Some(GateResult::ask(format!("gradle: {}", subcmd_single)))
}

// === MVN (from system.toml) ===

pub static MVN_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "help",
        "validate",
        "compile",
        "test",
        "package",
        "verify",
        "clean",
        "dependency:tree",
        "dependency:analyze",
    ]
    .into_iter()
    .collect()
});

pub static MVN_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing to local repo"),
        ("deploy", "Deploying artifacts"),
    ]
    .into_iter()
    .collect()
});

/// Check mvn commands declaratively
pub fn check_mvn_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mvn", "maven", "./mvnw", "mvnw"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if MVN_ALLOW.contains(subcmd.as_str()) || MVN_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = MVN_ASK
        .get(subcmd.as_str())
        .or_else(|| MVN_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("mvn: {}", reason)));
    }

    Some(GateResult::ask(format!("mvn: {}", subcmd_single)))
}

// === BAZEL (from system.toml) ===

pub static BAZEL_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "info", "query", "cquery", "aquery", "build", "test", "coverage", "version", "help",
    ]
    .into_iter()
    .collect()
});

pub static BAZEL_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [("clean", "Cleaning build"), ("run", "Running target")]
        .into_iter()
        .collect()
});

/// Check bazel commands declaratively
pub fn check_bazel_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["bazel", "bazelisk"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if BAZEL_ALLOW.contains(subcmd.as_str()) || BAZEL_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = BAZEL_ASK
        .get(subcmd.as_str())
        .or_else(|| BAZEL_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("bazel: {}", reason)));
    }

    Some(GateResult::ask(format!("bazel: {}", subcmd_single)))
}

// === MESON (from system.toml) ===

pub static MESON_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    ["introspect", "configure", "--version", "--help"]
        .into_iter()
        .collect()
});

pub static MESON_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("setup", "Setting up build"),
        ("compile", "Compiling project"),
        ("install", "Installing"),
    ]
    .into_iter()
    .collect()
});

/// Check meson commands declaratively
pub fn check_meson_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["meson"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if MESON_ALLOW.contains(subcmd.as_str()) || MESON_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = MESON_ASK
        .get(subcmd.as_str())
        .or_else(|| MESON_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("meson: {}", reason)));
    }

    Some(GateResult::ask(format!("meson: {}", subcmd_single)))
}

// === ANSIBLE (from system.toml) ===

pub static ANSIBLE_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "--version",
        "--help",
        "--list-hosts",
        "--list-tasks",
        "--syntax-check",
    ]
    .into_iter()
    .collect()
});

/// Check ansible commands declaratively
pub fn check_ansible_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if ![
        "ansible",
        "ansible-playbook",
        "ansible-galaxy",
        "ansible-vault",
    ]
    .contains(&cmd.program.as_str())
    {
        return None;
    }

    // Check allow_if_flags (e.g., --dry-run)
    if cmd
        .args
        .iter()
        .any(|a| ["--check", "-C", "--diff"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if ANSIBLE_ALLOW.contains(subcmd.as_str()) || ANSIBLE_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any ansible invocation asks
    Some(GateResult::ask("ansible: Running playbook"))
}

// === VAGRANT (from system.toml) ===

pub static VAGRANT_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "status",
        "global-status",
        "ssh-config",
        "port",
        "version",
        "--help",
    ]
    .into_iter()
    .collect()
});

pub static VAGRANT_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("up", "Starting VM"),
        ("halt", "Stopping VM"),
        ("destroy", "Destroying VM"),
        ("provision", "Provisioning VM"),
        ("ssh", "SSH into VM"),
        ("reload", "Reloading VM"),
    ]
    .into_iter()
    .collect()
});

/// Check vagrant commands declaratively
pub fn check_vagrant_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["vagrant"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if VAGRANT_ALLOW.contains(subcmd.as_str()) || VAGRANT_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = VAGRANT_ASK
        .get(subcmd.as_str())
        .or_else(|| VAGRANT_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("vagrant: {}", reason)));
    }

    Some(GateResult::ask(format!("vagrant: {}", subcmd_single)))
}

// === HYPERFINE (from system.toml) ===

pub static HYPERFINE_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "--help"].into_iter().collect());

/// Check hyperfine commands declaratively
pub fn check_hyperfine_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["hyperfine"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if HYPERFINE_ALLOW.contains(subcmd.as_str()) || HYPERFINE_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any hyperfine invocation asks
    Some(GateResult::ask("hyperfine: Running benchmarks"))
}

// === SUDO (from system.toml) ===

/// Check sudo commands declaratively
pub fn check_sudo_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["sudo", "doas"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-l", "--list"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-v", "--validate"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-k", "--reset-timestamp"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("sudo: {}", subcmd_single)))
}

// === SYSTEMCTL (from system.toml) ===

pub static SYSTEMCTL_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "status",
        "show",
        "list-units",
        "list-unit-files",
        "list-sockets",
        "list-timers",
        "list-jobs",
        "list-dependencies",
        "is-active",
        "is-enabled",
        "is-failed",
        "is-system-running",
        "cat",
        "help",
        "--version",
        "-h",
        "--help",
    ]
    .into_iter()
    .collect()
});

pub static SYSTEMCTL_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("start", "Starting service"),
        ("stop", "Stopping service"),
        ("restart", "Restarting service"),
        ("reload", "Reloading service"),
        ("enable", "Enabling service"),
        ("disable", "Disabling service"),
        ("mask", "Masking service"),
        ("unmask", "Unmasking service"),
        ("kill", "Killing service"),
        ("reset-failed", "Resetting failed state"),
        ("daemon-reload", "Reloading daemon"),
        ("daemon-reexec", "Re-executing daemon"),
        ("set-default", "Setting default target"),
        ("isolate", "Isolating target"),
        ("edit", "Editing unit"),
    ]
    .into_iter()
    .collect()
});

/// Check systemctl commands declaratively
pub fn check_systemctl_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["systemctl"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if SYSTEMCTL_ALLOW.contains(subcmd.as_str()) || SYSTEMCTL_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = SYSTEMCTL_ASK
        .get(subcmd.as_str())
        .or_else(|| SYSTEMCTL_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("systemctl: {}", reason)));
    }

    Some(GateResult::ask(format!("systemctl: {}", subcmd_single)))
}

// === SERVICE (from system.toml) ===

/// Check service commands declaratively
pub fn check_service_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["service"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--status-all"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("service: {}", subcmd_single)))
}

// === CRONTAB (from system.toml) ===

/// Check crontab commands declaratively
pub fn check_crontab_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["crontab"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check conditional allow rules
    if true && cmd.args.iter().any(|a| ["-l"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any crontab invocation asks
    Some(GateResult::ask("crontab: Modifying scheduled tasks"))
}

// === APT (from system.toml) ===

pub static APT_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list",
        "search",
        "show",
        "showpkg",
        "depends",
        "rdepends",
        "policy",
        "madison",
        "pkgnames",
        "dotty",
        "xvcg",
        "stats",
        "dump",
        "dumpavail",
        "showsrc",
        "changelog",
        "--version",
        "-v",
        "--help",
        "-h",
    ]
    .into_iter()
    .collect()
});

pub static APT_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        (
            "download",
            "Downloading package files (writes to local filesystem)",
        ),
        ("install", "Installing packages"),
        ("remove", "Removing packages"),
        ("purge", "Purging packages"),
        ("update", "Updating package lists"),
        ("upgrade", "Upgrading packages"),
        ("full-upgrade", "Full system upgrade"),
        ("dist-upgrade", "Distribution upgrade"),
        ("autoremove", "Removing unused packages"),
        ("autoclean", "Cleaning cache"),
        ("clean", "Cleaning cache"),
        ("build-dep", "Installing build dependencies"),
        ("source", "Downloading source"),
        ("edit-sources", "Editing sources"),
        ("satisfy", "Satisfying dependencies"),
    ]
    .into_iter()
    .collect()
});

/// Check apt commands declaratively
pub fn check_apt_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["apt", "apt-get"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if APT_ALLOW.contains(subcmd.as_str()) || APT_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = APT_ASK
        .get(subcmd.as_str())
        .or_else(|| APT_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("apt: {}", reason)));
    }

    Some(GateResult::ask(format!("apt: {}", subcmd_single)))
}

// === APT-CACHE (from system.toml) ===

/// Check apt-cache commands declaratively
pub fn check_apt_cache_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["apt-cache"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    Some(GateResult::allow())
}

// === DNF (from system.toml) ===

pub static DNF_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list",
        "info",
        "search",
        "provides",
        "whatprovides",
        "repolist",
        "repoinfo",
        "repoquery",
        "deplist",
        "check",
        "check-update",
        "history",
        "alias",
        "--version",
        "-v",
        "--help",
        "-h",
    ]
    .into_iter()
    .collect()
});

pub static DNF_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing packages"),
        ("remove", "Removing packages"),
        ("erase", "Removing packages"),
        ("update", "Updating packages"),
        ("upgrade", "Upgrading packages"),
        ("downgrade", "Downgrading packages"),
        ("reinstall", "Reinstalling packages"),
        ("autoremove", "Removing unused packages"),
        ("clean", "Cleaning cache"),
        ("makecache", "Building cache"),
        ("group", "Group operation"),
        ("module", "Module operation"),
        ("swap", "Swapping packages"),
        ("distro-sync", "Syncing distribution"),
    ]
    .into_iter()
    .collect()
});

/// Check dnf commands declaratively
pub fn check_dnf_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["dnf", "yum"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if DNF_ALLOW.contains(subcmd.as_str()) || DNF_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = DNF_ASK
        .get(subcmd.as_str())
        .or_else(|| DNF_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("dnf: {}", reason)));
    }

    Some(GateResult::ask(format!("dnf: {}", subcmd_single)))
}

// === PACMAN (from system.toml) ===

pub static PACMAN_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "-Q",
        "--query",
        "-Qs",
        "-Qi",
        "-Ql",
        "-Qo",
        "-Ss",
        "-Si",
        "-Sl",
        "-Sg",
        "-F",
        "--files",
        "-V",
        "--version",
        "-h",
        "--help",
    ]
    .into_iter()
    .collect()
});

/// Check pacman commands declaratively
pub fn check_pacman_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pacman", "yay", "paru"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if PACMAN_ALLOW.contains(subcmd.as_str()) || PACMAN_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("pacman: {}", subcmd_single)))
}

// === BREW (from system.toml) ===

pub static BREW_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list",
        "ls",
        "search",
        "info",
        "home",
        "homepage",
        "deps",
        "uses",
        "leaves",
        "outdated",
        "config",
        "doctor",
        "commands",
        "desc",
        "--version",
        "-v",
        "--help",
        "-h",
        "cat",
        "formula",
        "cask",
    ]
    .into_iter()
    .collect()
});

pub static BREW_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing packages"),
        ("uninstall", "Uninstalling packages"),
        ("remove", "Removing packages"),
        ("upgrade", "Upgrading packages"),
        ("update", "Updating Homebrew"),
        ("reinstall", "Reinstalling packages"),
        ("link", "Linking packages"),
        ("unlink", "Unlinking packages"),
        ("pin", "Pinning packages"),
        ("unpin", "Unpinning packages"),
        ("tap", "Tapping repository"),
        ("untap", "Untapping repository"),
        ("cleanup", "Cleaning up"),
        ("autoremove", "Removing unused"),
        ("services", "Managing services"),
    ]
    .into_iter()
    .collect()
});

/// Check brew commands declaratively
pub fn check_brew_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["brew"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if BREW_ALLOW.contains(subcmd.as_str()) || BREW_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = BREW_ASK
        .get(subcmd.as_str())
        .or_else(|| BREW_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("brew: {}", reason)));
    }

    Some(GateResult::ask(format!("brew: {}", subcmd_single)))
}

// === ZYPPER (from system.toml) ===

pub static ZYPPER_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "search",
        "se",
        "info",
        "if",
        "list-updates",
        "lu",
        "packages",
        "pa",
        "patterns",
        "pt",
        "products",
        "pd",
        "repos",
        "lr",
        "services",
        "ls",
        "--version",
        "-V",
        "--help",
        "-h",
    ]
    .into_iter()
    .collect()
});

pub static ZYPPER_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing packages"),
        ("in", "Installing packages"),
        ("remove", "Removing packages"),
        ("rm", "Removing packages"),
        ("update", "Updating packages"),
        ("up", "Updating packages"),
        ("dist-upgrade", "Distribution upgrade"),
        ("dup", "Distribution upgrade"),
        ("patch", "Installing patches"),
        ("addrepo", "Adding repository"),
        ("ar", "Adding repository"),
        ("removerepo", "Removing repository"),
        ("rr", "Removing repository"),
        ("refresh", "Refreshing repositories"),
        ("ref", "Refreshing repositories"),
        ("clean", "Cleaning cache"),
    ]
    .into_iter()
    .collect()
});

/// Check zypper commands declaratively
pub fn check_zypper_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["zypper"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if ZYPPER_ALLOW.contains(subcmd.as_str()) || ZYPPER_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = ZYPPER_ASK
        .get(subcmd.as_str())
        .or_else(|| ZYPPER_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("zypper: {}", reason)));
    }

    Some(GateResult::ask(format!("zypper: {}", subcmd_single)))
}

// === APK (from system.toml) ===

pub static APK_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "info",
        "list",
        "search",
        "dot",
        "policy",
        "stats",
        "audit",
        "--version",
        "-V",
        "--help",
        "-h",
    ]
    .into_iter()
    .collect()
});

pub static APK_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("add", "Installing packages"),
        ("del", "Removing packages"),
        ("update", "Updating index"),
        ("upgrade", "Upgrading packages"),
        ("fix", "Fixing packages"),
        ("cache", "Cache operation"),
        ("fetch", "Fetching packages"),
    ]
    .into_iter()
    .collect()
});

/// Check apk commands declaratively
pub fn check_apk_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["apk"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if APK_ALLOW.contains(subcmd.as_str()) || APK_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = APK_ASK
        .get(subcmd.as_str())
        .or_else(|| APK_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("apk: {}", reason)));
    }

    Some(GateResult::ask(format!("apk: {}", subcmd_single)))
}

// === NIX (from system.toml) ===

pub static NIX_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "search",
        "show",
        "eval",
        "repl",
        "flake",
        "path-info",
        "derivation",
        "store",
        "log",
        "why-depends",
        "--version",
        "--help",
    ]
    .into_iter()
    .collect()
});

pub static NIX_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("build", "Building derivation"),
        ("develop", "Entering dev shell"),
        ("run", "Running package"),
        ("shell", "Entering shell"),
        ("profile", "Profile operation"),
        ("upgrade-nix", "Upgrading Nix"),
        ("copy", "Copying paths"),
        ("collect-garbage", "Collecting garbage"),
    ]
    .into_iter()
    .collect()
});

/// Check nix commands declaratively
pub fn check_nix_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["nix"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if NIX_ALLOW.contains(subcmd.as_str()) || NIX_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = NIX_ASK
        .get(subcmd.as_str())
        .or_else(|| NIX_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("nix: {}", reason)));
    }

    Some(GateResult::ask(format!("nix: {}", subcmd_single)))
}

// === NIX-ENV (from system.toml) ===

pub static NIX_ENV_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["-q", "--query"].into_iter().collect());

pub static NIX_ENV_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("-i", "Installing packages"),
        ("--install", "Installing packages"),
        ("-e", "Uninstalling packages"),
        ("--uninstall", "Uninstalling packages"),
        ("-u", "Upgrading packages"),
        ("--upgrade", "Upgrading packages"),
    ]
    .into_iter()
    .collect()
});

/// Check nix-env commands declaratively
pub fn check_nix_env_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["nix-env"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if NIX_ENV_ALLOW.contains(subcmd.as_str()) || NIX_ENV_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = NIX_ENV_ASK
        .get(subcmd.as_str())
        .or_else(|| NIX_ENV_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("nix-env: {}", reason)));
    }

    Some(GateResult::ask(format!("nix-env: {}", subcmd_single)))
}

// === NIX-SHELL (from system.toml) ===

/// Check nix-shell commands declaratively
pub fn check_nix_shell_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["nix-shell"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Bare ask rule - any nix-shell invocation asks
    Some(GateResult::ask("nix-shell: Entering Nix shell"))
}

// === FLATPAK (from system.toml) ===

pub static FLATPAK_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list",
        "info",
        "search",
        "remote-ls",
        "remotes",
        "history",
        "--version",
        "--help",
    ]
    .into_iter()
    .collect()
});

pub static FLATPAK_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing"),
        ("uninstall", "Uninstalling"),
        ("remove", "Removing"),
        ("update", "Updating"),
        ("upgrade", "Upgrading"),
        ("run", "Running"),
        ("remote-add", "Adding remote"),
        ("remote-delete", "Removing remote"),
        ("repair", "Repairing"),
    ]
    .into_iter()
    .collect()
});

/// Check flatpak commands declaratively
pub fn check_flatpak_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["flatpak", "snap"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    if FLATPAK_ALLOW.contains(subcmd.as_str()) || FLATPAK_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = FLATPAK_ASK
        .get(subcmd.as_str())
        .or_else(|| FLATPAK_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("flatpak: {}", reason)));
    }

    Some(GateResult::ask(format!("flatpak: {}", subcmd_single)))
}

// === SHORT (from shortcut.toml) ===

pub static SHORT_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Configuring Shortcut API token"),
        ("create", "Creating new story"),
    ]
    .into_iter()
    .collect()
});

/// Check short commands declaratively
pub fn check_short_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["short"].contains(&cmd.program.as_str()) {
        return None;
    }

    #[allow(unused_variables)]
    let subcmd = if cmd.args.is_empty() {
        String::new()
    } else if cmd.args.len() == 1 {
        cmd.args[0].clone()
    } else {
        format!("{} {}", cmd.args[0], cmd.args[1])
    };
    #[allow(unused_variables)]
    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or("");

    // Check ask rules with flag/prefix conditions
    if subcmd_single == "search"
        && cmd
            .args
            .iter()
            .any(|a| ["-S", "--save"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Saving workspace to config"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["--git-branch", "--git-branch-short"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Checking out git branch"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["-D", "--download"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Downloading attachments to disk"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["-c", "--comment"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Adding comment to story"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["-d", "--description"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Updating story description"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["-e", "--estimate"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Updating story estimate"));
    }
    if subcmd_single == "story" && cmd.args.iter().any(|a| ["--epic"].contains(&a.as_str())) {
        return Some(GateResult::ask("Setting story epic"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["-i", "--iteration"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Setting story iteration"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["-l", "--label"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Updating story labels"));
    }
    if subcmd_single == "story"
        && cmd.args.iter().any(|a| {
            ["--move-after", "--move-before", "--move-down", "--move-up"].contains(&a.as_str())
        })
    {
        return Some(GateResult::ask("Moving story position"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["-o", "--owners"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Updating story owners"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["-s", "--state"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Updating story state"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["-t", "--title"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Updating story title"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["-T", "--team"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Updating story team"));
    }
    if subcmd_single == "story" && cmd.args.iter().any(|a| ["--task"].contains(&a.as_str())) {
        return Some(GateResult::ask("Creating task on story"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["--task-complete"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Toggling task completion"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["-y", "--type"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Updating story type"));
    }
    if subcmd_single == "story"
        && cmd
            .args
            .iter()
            .any(|a| ["-a", "--archived"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Archiving story"));
    }
    if subcmd_single == "workspace"
        && cmd
            .args
            .iter()
            .any(|a| ["-u", "--unset"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Removing saved workspace"));
    }

    // Check conditional allow rules
    if subcmd_single == "search" {
        return Some(GateResult::allow_with_reason("Searching stories"));
    }
    if subcmd_single == "find" {
        return Some(GateResult::allow_with_reason("Searching stories"));
    }
    if subcmd_single == "story" {
        return Some(GateResult::allow_with_reason("Viewing story"));
    }
    if subcmd_single == "members" {
        return Some(GateResult::allow_with_reason("Listing members"));
    }
    if subcmd_single == "epics" {
        return Some(GateResult::allow_with_reason("Listing epics"));
    }
    if subcmd_single == "workflows" {
        return Some(GateResult::allow_with_reason("Listing workflows"));
    }
    if subcmd_single == "projects" {
        return Some(GateResult::allow_with_reason("Listing projects"));
    }
    if subcmd_single == "workspace" {
        return Some(GateResult::allow_with_reason("Listing workspaces"));
    }
    if subcmd_single == "help" {
        return Some(GateResult::allow_with_reason("Showing help"));
    }

    if let Some(reason) = SHORT_ASK
        .get(subcmd.as_str())
        .or_else(|| SHORT_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("short: {}", reason)));
    }

    Some(GateResult::ask(format!("short: {}", subcmd_single)))
}

/// Check command against all declarative rules
/// Returns Some(GateResult) if handled by declarative rules, None otherwise
pub fn check_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    // Check safe commands first
    if let Some(result) = check_safe_command(cmd) {
        return Some(result);
    }

    // Check conditional allow rules
    if let Some(result) = check_conditional_allow(cmd) {
        return Some(result);
    }

    // Check program-specific rules
    if let Some(result) = check_mcp_cli_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_gh_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_git_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_aws_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_gcloud_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_az_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_terraform_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_kubectl_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_docker_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_podman_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_docker_compose_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_helm_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_pulumi_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_npm_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_pnpm_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_yarn_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_pip_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_uv_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_cargo_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_rustc_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_rustup_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_go_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_bun_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_conda_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_poetry_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_pipx_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_mise_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_bd_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_tool_gates_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_sd_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_sad_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_ast_grep_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_yq_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_jq_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_semgrep_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_comby_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_grit_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_watchexec_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_biome_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_prettier_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_eslint_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_ruff_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_black_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_isort_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_shellcheck_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_hadolint_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_golangci_lint_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_gci_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_air_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_actionlint_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_gitleaks_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_lefthook_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_vite_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_vitest_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_jest_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_mocha_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_tsc_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_tsup_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_esbuild_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_turbo_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_nx_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_knip_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_oxlint_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_gofmt_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_goimports_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_shfmt_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_rustfmt_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_stylua_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_clang_format_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_autopep8_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_rubocop_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_standardrb_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_patch_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_dos2unix_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_unix2dos_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_stylelint_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_mix_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_perltidy_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_dartfmt_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_dart_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_elm_format_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_scalafmt_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_ktlint_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_swiftformat_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_buf_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_rm_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_mv_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_cp_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_mkdir_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_rmdir_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_touch_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_chmod_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_chown_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_chgrp_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_ln_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_perl_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_tar_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_unzip_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_zip_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_curl_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_wget_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_ssh_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_scp_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_sftp_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_rsync_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_nc_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_http_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_shutdown_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_reboot_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_poweroff_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_halt_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_init_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_mkfs_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_fdisk_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_parted_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_gdisk_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_dd_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_shred_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_wipe_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_mke2fs_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_mkswap_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_wipefs_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_hdparm_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_insmod_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_rmmod_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_modprobe_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_grub_install_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_update_grub_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_useradd_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_userdel_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_usermod_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_passwd_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_chsh_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_iptables_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_ufw_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_firewall_cmd_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_chattr_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_mount_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_umount_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_swapoff_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_swapon_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_lvremove_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_vgremove_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_pvremove_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_psql_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_createdb_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_dropdb_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_pg_dump_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_pg_restore_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_migrate_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_goose_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_dbmate_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_flyway_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_alembic_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_mysql_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_sqlite3_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_mongosh_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_redis_cli_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_kill_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_pkill_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_killall_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_xkill_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_make_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_cmake_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_ninja_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_just_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_task_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_gradle_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_mvn_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_bazel_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_meson_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_ansible_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_vagrant_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_hyperfine_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_sudo_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_systemctl_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_service_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_crontab_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_apt_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_apt_cache_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_dnf_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_pacman_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_brew_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_zypper_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_apk_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_nix_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_nix_env_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_nix_shell_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_flatpak_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_short_declarative(cmd) {
        return Some(result);
    }

    None
}
// === Generated Gate Functions ===
// These replace manual routing in gate files.
// Add tool to TOML, rebuild, done - no Rust changes needed.

/// Generated gate for mcp - handles: mcp-cli
/// Custom handlers needed for: ["mcp-cli"]
pub fn check_mcp_gate(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "mcp-cli" => GateResult::skip(), // custom handler: check_mcp_call
        _ => GateResult::skip(),
    }
}

/// Programs handled by the mcp gate
pub static MCP_PROGRAMS: &[&str] = &["mcp-cli"];

/// Generated gate for gh - handles: gh
/// Custom handlers needed for: []
pub fn check_gh_gate(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "gh" => check_gh_declarative(cmd).unwrap_or_else(GateResult::skip),
        _ => GateResult::skip(),
    }
}

/// Programs handled by the gh gate
pub static GH_PROGRAMS: &[&str] = &["gh"];

/// Generated gate for git - handles: git
/// Custom handlers needed for: ["git"]
pub fn check_git_gate(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "git" => GateResult::skip(), // custom handler: extract_subcommand
        _ => GateResult::skip(),
    }
}

/// Programs handled by the git gate
pub static GIT_PROGRAMS: &[&str] = &["git"];

/// Generated gate for cloud - handles: aws, gcloud, az, terraform, tofu, kubectl, k, docker, podman, docker-compose, podman-compose, helm, pulumi
/// Custom handlers needed for: ["docker", "gcloud"]
pub fn check_cloud_gate(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "aws" => check_aws_declarative(cmd).unwrap_or_else(GateResult::skip),
        "gcloud" => GateResult::skip(), // custom handler: check_gcloud
        "az" => check_az_declarative(cmd).unwrap_or_else(GateResult::skip),
        "terraform" | "tofu" => check_terraform_declarative(cmd).unwrap_or_else(GateResult::skip),
        "kubectl" | "k" => check_kubectl_declarative(cmd).unwrap_or_else(GateResult::skip),
        "docker" => GateResult::skip(), // custom handler: check_docker
        "podman" => check_podman_declarative(cmd).unwrap_or_else(GateResult::skip),
        "docker-compose" | "podman-compose" => {
            check_docker_compose_declarative(cmd).unwrap_or_else(GateResult::skip)
        }
        "helm" => check_helm_declarative(cmd).unwrap_or_else(GateResult::skip),
        "pulumi" => check_pulumi_declarative(cmd).unwrap_or_else(GateResult::skip),
        _ => GateResult::skip(),
    }
}

/// Programs handled by the cloud gate
pub static CLOUD_PROGRAMS: &[&str] = &[
    "aws",
    "gcloud",
    "az",
    "terraform",
    "tofu",
    "kubectl",
    "k",
    "docker",
    "podman",
    "docker-compose",
    "podman-compose",
    "helm",
    "pulumi",
];

/// Generated gate for package_managers - handles: npm, pnpm, yarn, pip, pip3, uv, cargo, rustc, rustup, go, bun, conda, mamba, micromamba, poetry, pipx, mise
/// Custom handlers needed for: ["mise", "npm", "pip", "pipx", "pnpm", "poetry", "uv", "yarn"]
pub fn check_package_managers_gate(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "npm" => GateResult::skip(),          // custom handler: check_npm
        "pnpm" => GateResult::skip(),         // custom handler: check_pnpm
        "yarn" => GateResult::skip(),         // custom handler: check_yarn
        "pip" | "pip3" => GateResult::skip(), // custom handler: check_pip
        "uv" => GateResult::skip(),           // custom handler: check_uv
        "cargo" => check_cargo_declarative(cmd).unwrap_or_else(GateResult::skip),
        "rustc" => check_rustc_declarative(cmd).unwrap_or_else(GateResult::skip),
        "rustup" => check_rustup_declarative(cmd).unwrap_or_else(GateResult::skip),
        "go" => check_go_declarative(cmd).unwrap_or_else(GateResult::skip),
        "bun" => check_bun_declarative(cmd).unwrap_or_else(GateResult::skip),
        "conda" | "mamba" | "micromamba" => {
            check_conda_declarative(cmd).unwrap_or_else(GateResult::skip)
        }
        "poetry" => GateResult::skip(), // custom handler: check_poetry
        "pipx" => GateResult::skip(),   // custom handler: check_pipx
        "mise" => GateResult::skip(),   // custom handler: check_mise
        _ => GateResult::skip(),
    }
}

/// Programs handled by the package_managers gate
pub static PACKAGE_MANAGERS_PROGRAMS: &[&str] = &[
    "npm",
    "pnpm",
    "yarn",
    "pip",
    "pip3",
    "uv",
    "cargo",
    "rustc",
    "rustup",
    "go",
    "bun",
    "conda",
    "mamba",
    "micromamba",
    "poetry",
    "pipx",
    "mise",
];

/// Generated gate for beads - handles: bd, beads
/// Custom handlers needed for: []
pub fn check_beads_gate(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "bd" | "beads" => check_bd_declarative(cmd).unwrap_or_else(GateResult::skip),
        _ => GateResult::skip(),
    }
}

/// Programs handled by the beads gate
pub static BEADS_PROGRAMS: &[&str] = &["bd", "beads"];

/// Generated gate for tool_gates - handles: tool-gates, bash-gates
/// Custom handlers needed for: []
pub fn check_tool_gates_gate(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "tool-gates" | "bash-gates" => {
            check_tool_gates_declarative(cmd).unwrap_or_else(GateResult::skip)
        }
        _ => GateResult::skip(),
    }
}

/// Programs handled by the tool_gates gate
pub static TOOL_GATES_PROGRAMS: &[&str] = &["tool-gates", "bash-gates"];

/// Generated gate for devtools - handles: sd, sad, ast-grep, sg, yq, jq, semgrep, comby, grit, watchexec, biome, prettier, eslint, ruff, black, isort, shellcheck, hadolint, golangci-lint, gci, air, actionlint, gitleaks, lefthook, vite, vitest, jest, mocha, tsc, tsup, esbuild, turbo, nx, knip, oxlint, gofmt, goimports, shfmt, rustfmt, stylua, clang-format, autopep8, rubocop, standardrb, patch, dos2unix, unix2dos, stylelint, mix, perltidy, dartfmt, dart, elm-format, scalafmt, ktlint, swiftformat, buf
/// Custom handlers needed for: ["sd"]
pub fn check_devtools_gate(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "sd" => GateResult::skip(), // custom handler: check_sd
        "sad" => check_sad_declarative(cmd).unwrap_or_else(GateResult::skip),
        "ast-grep" | "sg" => check_ast_grep_declarative(cmd).unwrap_or_else(GateResult::skip),
        "yq" => check_yq_declarative(cmd).unwrap_or_else(GateResult::skip),
        "jq" => check_jq_declarative(cmd).unwrap_or_else(GateResult::skip),
        "semgrep" => check_semgrep_declarative(cmd).unwrap_or_else(GateResult::skip),
        "comby" => check_comby_declarative(cmd).unwrap_or_else(GateResult::skip),
        "grit" => check_grit_declarative(cmd).unwrap_or_else(GateResult::skip),
        "watchexec" => check_watchexec_declarative(cmd).unwrap_or_else(GateResult::skip),
        "biome" => check_biome_declarative(cmd).unwrap_or_else(GateResult::skip),
        "prettier" => check_prettier_declarative(cmd).unwrap_or_else(GateResult::skip),
        "eslint" => check_eslint_declarative(cmd).unwrap_or_else(GateResult::skip),
        "ruff" => check_ruff_declarative(cmd).unwrap_or_else(GateResult::skip),
        "black" => check_black_declarative(cmd).unwrap_or_else(GateResult::skip),
        "isort" => check_isort_declarative(cmd).unwrap_or_else(GateResult::skip),
        "shellcheck" => check_shellcheck_declarative(cmd).unwrap_or_else(GateResult::skip),
        "hadolint" => check_hadolint_declarative(cmd).unwrap_or_else(GateResult::skip),
        "golangci-lint" => check_golangci_lint_declarative(cmd).unwrap_or_else(GateResult::skip),
        "gci" => check_gci_declarative(cmd).unwrap_or_else(GateResult::skip),
        "air" => check_air_declarative(cmd).unwrap_or_else(GateResult::skip),
        "actionlint" => check_actionlint_declarative(cmd).unwrap_or_else(GateResult::skip),
        "gitleaks" => check_gitleaks_declarative(cmd).unwrap_or_else(GateResult::skip),
        "lefthook" => check_lefthook_declarative(cmd).unwrap_or_else(GateResult::skip),
        "vite" => check_vite_declarative(cmd).unwrap_or_else(GateResult::skip),
        "vitest" => check_vitest_declarative(cmd).unwrap_or_else(GateResult::skip),
        "jest" => check_jest_declarative(cmd).unwrap_or_else(GateResult::skip),
        "mocha" => check_mocha_declarative(cmd).unwrap_or_else(GateResult::skip),
        "tsc" => check_tsc_declarative(cmd).unwrap_or_else(GateResult::skip),
        "tsup" => check_tsup_declarative(cmd).unwrap_or_else(GateResult::skip),
        "esbuild" => check_esbuild_declarative(cmd).unwrap_or_else(GateResult::skip),
        "turbo" => check_turbo_declarative(cmd).unwrap_or_else(GateResult::skip),
        "nx" => check_nx_declarative(cmd).unwrap_or_else(GateResult::skip),
        "knip" => check_knip_declarative(cmd).unwrap_or_else(GateResult::skip),
        "oxlint" => check_oxlint_declarative(cmd).unwrap_or_else(GateResult::skip),
        "gofmt" => check_gofmt_declarative(cmd).unwrap_or_else(GateResult::skip),
        "goimports" => check_goimports_declarative(cmd).unwrap_or_else(GateResult::skip),
        "shfmt" => check_shfmt_declarative(cmd).unwrap_or_else(GateResult::skip),
        "rustfmt" => check_rustfmt_declarative(cmd).unwrap_or_else(GateResult::skip),
        "stylua" => check_stylua_declarative(cmd).unwrap_or_else(GateResult::skip),
        "clang-format" => check_clang_format_declarative(cmd).unwrap_or_else(GateResult::skip),
        "autopep8" => check_autopep8_declarative(cmd).unwrap_or_else(GateResult::skip),
        "rubocop" => check_rubocop_declarative(cmd).unwrap_or_else(GateResult::skip),
        "standardrb" => check_standardrb_declarative(cmd).unwrap_or_else(GateResult::skip),
        "patch" => check_patch_declarative(cmd).unwrap_or_else(GateResult::skip),
        "dos2unix" => check_dos2unix_declarative(cmd).unwrap_or_else(GateResult::skip),
        "unix2dos" => check_unix2dos_declarative(cmd).unwrap_or_else(GateResult::skip),
        "stylelint" => check_stylelint_declarative(cmd).unwrap_or_else(GateResult::skip),
        "mix" => check_mix_declarative(cmd).unwrap_or_else(GateResult::skip),
        "perltidy" => check_perltidy_declarative(cmd).unwrap_or_else(GateResult::skip),
        "dartfmt" => check_dartfmt_declarative(cmd).unwrap_or_else(GateResult::skip),
        "dart" => check_dart_declarative(cmd).unwrap_or_else(GateResult::skip),
        "elm-format" => check_elm_format_declarative(cmd).unwrap_or_else(GateResult::skip),
        "scalafmt" => check_scalafmt_declarative(cmd).unwrap_or_else(GateResult::skip),
        "ktlint" => check_ktlint_declarative(cmd).unwrap_or_else(GateResult::skip),
        "swiftformat" => check_swiftformat_declarative(cmd).unwrap_or_else(GateResult::skip),
        "buf" => check_buf_declarative(cmd).unwrap_or_else(GateResult::skip),
        _ => GateResult::skip(),
    }
}

/// Programs handled by the devtools gate
pub static DEVTOOLS_PROGRAMS: &[&str] = &[
    "sd",
    "sad",
    "ast-grep",
    "sg",
    "yq",
    "jq",
    "semgrep",
    "comby",
    "grit",
    "watchexec",
    "biome",
    "prettier",
    "eslint",
    "ruff",
    "black",
    "isort",
    "shellcheck",
    "hadolint",
    "golangci-lint",
    "gci",
    "air",
    "actionlint",
    "gitleaks",
    "lefthook",
    "vite",
    "vitest",
    "jest",
    "mocha",
    "tsc",
    "tsup",
    "esbuild",
    "turbo",
    "nx",
    "knip",
    "oxlint",
    "gofmt",
    "goimports",
    "shfmt",
    "rustfmt",
    "stylua",
    "clang-format",
    "autopep8",
    "rubocop",
    "standardrb",
    "patch",
    "dos2unix",
    "unix2dos",
    "stylelint",
    "mix",
    "perltidy",
    "dartfmt",
    "dart",
    "elm-format",
    "scalafmt",
    "ktlint",
    "swiftformat",
    "buf",
];

/// Generated gate for filesystem - handles: rm, mv, cp, mkdir, rmdir, touch, chmod, chown, chgrp, ln, perl, tar, unzip, zip
/// Custom handlers needed for: ["rm", "tar"]
pub fn check_filesystem_gate(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "rm" => GateResult::skip(), // custom handler: check_rm
        "mv" => check_mv_declarative(cmd).unwrap_or_else(GateResult::skip),
        "cp" => check_cp_declarative(cmd).unwrap_or_else(GateResult::skip),
        "mkdir" => check_mkdir_declarative(cmd).unwrap_or_else(GateResult::skip),
        "rmdir" => check_rmdir_declarative(cmd).unwrap_or_else(GateResult::skip),
        "touch" => check_touch_declarative(cmd).unwrap_or_else(GateResult::skip),
        "chmod" => check_chmod_declarative(cmd).unwrap_or_else(GateResult::skip),
        "chown" => check_chown_declarative(cmd).unwrap_or_else(GateResult::skip),
        "chgrp" => check_chgrp_declarative(cmd).unwrap_or_else(GateResult::skip),
        "ln" => check_ln_declarative(cmd).unwrap_or_else(GateResult::skip),
        "perl" => check_perl_declarative(cmd).unwrap_or_else(GateResult::skip),
        "tar" => GateResult::skip(), // custom handler: check_tar
        "unzip" => check_unzip_declarative(cmd).unwrap_or_else(GateResult::skip),
        "zip" => check_zip_declarative(cmd).unwrap_or_else(GateResult::skip),
        _ => GateResult::skip(),
    }
}

/// Programs handled by the filesystem gate
pub static FILESYSTEM_PROGRAMS: &[&str] = &[
    "rm", "mv", "cp", "mkdir", "rmdir", "touch", "chmod", "chown", "chgrp", "ln", "perl", "tar",
    "unzip", "zip",
];

/// Generated gate for network - handles: curl, wget, ssh, scp, sftp, rsync, nc, ncat, netcat, http, https, xh
/// Custom handlers needed for: ["curl", "http", "nc", "rsync", "wget"]
pub fn check_network_gate(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "curl" => GateResult::skip(), // custom handler: check_curl
        "wget" => GateResult::skip(), // custom handler: check_wget
        "ssh" => check_ssh_declarative(cmd).unwrap_or_else(GateResult::skip),
        "scp" => check_scp_declarative(cmd).unwrap_or_else(GateResult::skip),
        "sftp" => check_sftp_declarative(cmd).unwrap_or_else(GateResult::skip),
        "rsync" => GateResult::skip(), // custom handler: check_rsync
        "nc" | "ncat" | "netcat" => GateResult::skip(), // custom handler: check_netcat
        "http" | "https" | "xh" => GateResult::skip(), // custom handler: check_httpie
        _ => GateResult::skip(),
    }
}

/// Programs handled by the network gate
pub static NETWORK_PROGRAMS: &[&str] = &[
    "curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "http", "https", "xh",
];

/// Generated gate for system - handles: shutdown, reboot, poweroff, halt, init, mkfs, fdisk, parted, gdisk, dd, shred, wipe, mke2fs, mkswap, wipefs, hdparm, insmod, rmmod, modprobe, grub-install, update-grub, useradd, userdel, usermod, passwd, chsh, iptables, ufw, firewall-cmd, chattr, mount, umount, swapoff, swapon, lvremove, vgremove, pvremove, psql, createdb, dropdb, pg_dump, pg_restore, migrate, goose, dbmate, flyway, alembic, mysql, sqlite3, mongosh, mongo, redis-cli, kill, pkill, killall, xkill, make, cmake, ninja, just, task, gradle, gradlew, ./gradlew, mvn, maven, ./mvnw, mvnw, bazel, bazelisk, meson, ansible, ansible-playbook, ansible-galaxy, ansible-vault, vagrant, hyperfine, sudo, doas, systemctl, service, crontab, apt, apt-get, apt-cache, dnf, yum, pacman, yay, paru, brew, zypper, apk, nix, nix-env, nix-shell, flatpak, snap
/// Custom handlers needed for: ["apt", "brew", "crontab", "dnf", "kill", "make", "mysql", "pacman", "pkill", "psql", "sudo", "systemctl"]
pub fn check_system_gate(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "shutdown" => check_shutdown_declarative(cmd).unwrap_or_else(GateResult::skip),
        "reboot" => check_reboot_declarative(cmd).unwrap_or_else(GateResult::skip),
        "poweroff" => check_poweroff_declarative(cmd).unwrap_or_else(GateResult::skip),
        "halt" => check_halt_declarative(cmd).unwrap_or_else(GateResult::skip),
        "init" => check_init_declarative(cmd).unwrap_or_else(GateResult::skip),
        "mkfs" => check_mkfs_declarative(cmd).unwrap_or_else(GateResult::skip),
        "fdisk" => check_fdisk_declarative(cmd).unwrap_or_else(GateResult::skip),
        "parted" => check_parted_declarative(cmd).unwrap_or_else(GateResult::skip),
        "gdisk" => check_gdisk_declarative(cmd).unwrap_or_else(GateResult::skip),
        "dd" => check_dd_declarative(cmd).unwrap_or_else(GateResult::skip),
        "shred" => check_shred_declarative(cmd).unwrap_or_else(GateResult::skip),
        "wipe" => check_wipe_declarative(cmd).unwrap_or_else(GateResult::skip),
        "mke2fs" => check_mke2fs_declarative(cmd).unwrap_or_else(GateResult::skip),
        "mkswap" => check_mkswap_declarative(cmd).unwrap_or_else(GateResult::skip),
        "wipefs" => check_wipefs_declarative(cmd).unwrap_or_else(GateResult::skip),
        "hdparm" => check_hdparm_declarative(cmd).unwrap_or_else(GateResult::skip),
        "insmod" => check_insmod_declarative(cmd).unwrap_or_else(GateResult::skip),
        "rmmod" => check_rmmod_declarative(cmd).unwrap_or_else(GateResult::skip),
        "modprobe" => check_modprobe_declarative(cmd).unwrap_or_else(GateResult::skip),
        "grub-install" => check_grub_install_declarative(cmd).unwrap_or_else(GateResult::skip),
        "update-grub" => check_update_grub_declarative(cmd).unwrap_or_else(GateResult::skip),
        "useradd" => check_useradd_declarative(cmd).unwrap_or_else(GateResult::skip),
        "userdel" => check_userdel_declarative(cmd).unwrap_or_else(GateResult::skip),
        "usermod" => check_usermod_declarative(cmd).unwrap_or_else(GateResult::skip),
        "passwd" => check_passwd_declarative(cmd).unwrap_or_else(GateResult::skip),
        "chsh" => check_chsh_declarative(cmd).unwrap_or_else(GateResult::skip),
        "iptables" => check_iptables_declarative(cmd).unwrap_or_else(GateResult::skip),
        "ufw" => check_ufw_declarative(cmd).unwrap_or_else(GateResult::skip),
        "firewall-cmd" => check_firewall_cmd_declarative(cmd).unwrap_or_else(GateResult::skip),
        "chattr" => check_chattr_declarative(cmd).unwrap_or_else(GateResult::skip),
        "mount" => check_mount_declarative(cmd).unwrap_or_else(GateResult::skip),
        "umount" => check_umount_declarative(cmd).unwrap_or_else(GateResult::skip),
        "swapoff" => check_swapoff_declarative(cmd).unwrap_or_else(GateResult::skip),
        "swapon" => check_swapon_declarative(cmd).unwrap_or_else(GateResult::skip),
        "lvremove" => check_lvremove_declarative(cmd).unwrap_or_else(GateResult::skip),
        "vgremove" => check_vgremove_declarative(cmd).unwrap_or_else(GateResult::skip),
        "pvremove" => check_pvremove_declarative(cmd).unwrap_or_else(GateResult::skip),
        "psql" => GateResult::skip(), // custom handler: check_psql
        "createdb" => check_createdb_declarative(cmd).unwrap_or_else(GateResult::skip),
        "dropdb" => check_dropdb_declarative(cmd).unwrap_or_else(GateResult::skip),
        "pg_dump" => check_pg_dump_declarative(cmd).unwrap_or_else(GateResult::skip),
        "pg_restore" => check_pg_restore_declarative(cmd).unwrap_or_else(GateResult::skip),
        "migrate" => check_migrate_declarative(cmd).unwrap_or_else(GateResult::skip),
        "goose" => check_goose_declarative(cmd).unwrap_or_else(GateResult::skip),
        "dbmate" => check_dbmate_declarative(cmd).unwrap_or_else(GateResult::skip),
        "flyway" => check_flyway_declarative(cmd).unwrap_or_else(GateResult::skip),
        "alembic" => check_alembic_declarative(cmd).unwrap_or_else(GateResult::skip),
        "mysql" => GateResult::skip(), // custom handler: check_mysql
        "sqlite3" => check_sqlite3_declarative(cmd).unwrap_or_else(GateResult::skip),
        "mongosh" | "mongo" => check_mongosh_declarative(cmd).unwrap_or_else(GateResult::skip),
        "redis-cli" => check_redis_cli_declarative(cmd).unwrap_or_else(GateResult::skip),
        "kill" => GateResult::skip(),  // custom handler: check_kill
        "pkill" => GateResult::skip(), // custom handler: check_pkill
        "killall" => check_killall_declarative(cmd).unwrap_or_else(GateResult::skip),
        "xkill" => check_xkill_declarative(cmd).unwrap_or_else(GateResult::skip),
        "make" => GateResult::skip(), // custom handler: check_make
        "cmake" => check_cmake_declarative(cmd).unwrap_or_else(GateResult::skip),
        "ninja" => check_ninja_declarative(cmd).unwrap_or_else(GateResult::skip),
        "just" => check_just_declarative(cmd).unwrap_or_else(GateResult::skip),
        "task" => check_task_declarative(cmd).unwrap_or_else(GateResult::skip),
        "gradle" | "gradlew" | "./gradlew" => {
            check_gradle_declarative(cmd).unwrap_or_else(GateResult::skip)
        }
        "mvn" | "maven" | "./mvnw" | "mvnw" => {
            check_mvn_declarative(cmd).unwrap_or_else(GateResult::skip)
        }
        "bazel" | "bazelisk" => check_bazel_declarative(cmd).unwrap_or_else(GateResult::skip),
        "meson" => check_meson_declarative(cmd).unwrap_or_else(GateResult::skip),
        "ansible" | "ansible-playbook" | "ansible-galaxy" | "ansible-vault" => {
            check_ansible_declarative(cmd).unwrap_or_else(GateResult::skip)
        }
        "vagrant" => check_vagrant_declarative(cmd).unwrap_or_else(GateResult::skip),
        "hyperfine" => check_hyperfine_declarative(cmd).unwrap_or_else(GateResult::skip),
        "sudo" | "doas" => GateResult::skip(), // custom handler: check_sudo
        "systemctl" => GateResult::skip(),     // custom handler: check_systemctl
        "service" => check_service_declarative(cmd).unwrap_or_else(GateResult::skip),
        "crontab" => GateResult::skip(), // custom handler: check_crontab
        "apt" | "apt-get" => GateResult::skip(), // custom handler: check_apt
        "apt-cache" => check_apt_cache_declarative(cmd).unwrap_or_else(GateResult::skip),
        "dnf" | "yum" => GateResult::skip(), // custom handler: check_dnf
        "pacman" | "yay" | "paru" => GateResult::skip(), // custom handler: check_pacman
        "brew" => GateResult::skip(),        // custom handler: check_brew
        "zypper" => check_zypper_declarative(cmd).unwrap_or_else(GateResult::skip),
        "apk" => check_apk_declarative(cmd).unwrap_or_else(GateResult::skip),
        "nix" => check_nix_declarative(cmd).unwrap_or_else(GateResult::skip),
        "nix-env" => check_nix_env_declarative(cmd).unwrap_or_else(GateResult::skip),
        "nix-shell" => check_nix_shell_declarative(cmd).unwrap_or_else(GateResult::skip),
        "flatpak" | "snap" => check_flatpak_declarative(cmd).unwrap_or_else(GateResult::skip),
        _ => GateResult::skip(),
    }
}

/// Programs handled by the system gate
pub static SYSTEM_PROGRAMS: &[&str] = &[
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "init",
    "mkfs",
    "fdisk",
    "parted",
    "gdisk",
    "dd",
    "shred",
    "wipe",
    "mke2fs",
    "mkswap",
    "wipefs",
    "hdparm",
    "insmod",
    "rmmod",
    "modprobe",
    "grub-install",
    "update-grub",
    "useradd",
    "userdel",
    "usermod",
    "passwd",
    "chsh",
    "iptables",
    "ufw",
    "firewall-cmd",
    "chattr",
    "mount",
    "umount",
    "swapoff",
    "swapon",
    "lvremove",
    "vgremove",
    "pvremove",
    "psql",
    "createdb",
    "dropdb",
    "pg_dump",
    "pg_restore",
    "migrate",
    "goose",
    "dbmate",
    "flyway",
    "alembic",
    "mysql",
    "sqlite3",
    "mongosh",
    "mongo",
    "redis-cli",
    "kill",
    "pkill",
    "killall",
    "xkill",
    "make",
    "cmake",
    "ninja",
    "just",
    "task",
    "gradle",
    "gradlew",
    "./gradlew",
    "mvn",
    "maven",
    "./mvnw",
    "mvnw",
    "bazel",
    "bazelisk",
    "meson",
    "ansible",
    "ansible-playbook",
    "ansible-galaxy",
    "ansible-vault",
    "vagrant",
    "hyperfine",
    "sudo",
    "doas",
    "systemctl",
    "service",
    "crontab",
    "apt",
    "apt-get",
    "apt-cache",
    "dnf",
    "yum",
    "pacman",
    "yay",
    "paru",
    "brew",
    "zypper",
    "apk",
    "nix",
    "nix-env",
    "nix-shell",
    "flatpak",
    "snap",
];

/// Generated gate for shortcut - handles: short
/// Custom handlers needed for: ["short"]
pub fn check_shortcut_gate(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "short" => GateResult::skip(), // custom handler: check_short_api
        _ => GateResult::skip(),
    }
}

/// Programs handled by the shortcut gate
pub static SHORTCUT_PROGRAMS: &[&str] = &["short"];

// ============================================================================
// File Editing Detection (generated from accept_edits_auto_allow rules)
// ============================================================================

/// Programs that have file-editing rules (generated from accept_edits_auto_allow)
pub static FILE_EDITING_PROGRAMS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "ast-grep",
        "autopep8",
        "biome",
        "black",
        "buf",
        "cargo",
        "clang-format",
        "comby",
        "dart",
        "dartfmt",
        "dos2unix",
        "elm-format",
        "eslint",
        "gci",
        "go",
        "gofmt",
        "goimports",
        "golangci-lint",
        "grit",
        "isort",
        "ktlint",
        "mix",
        "mkdir",
        "perltidy",
        "prettier",
        "rubocop",
        "ruff",
        "rustfmt",
        "sad",
        "scalafmt",
        "sd",
        "sed",
        "semgrep",
        "sg",
        "shfmt",
        "standardrb",
        "stylelint",
        "stylua",
        "swiftformat",
        "terraform",
        "tofu",
        "unix2dos",
        "yq",
    ]
    .into_iter()
    .collect()
});

/// Check if a command is a file-editing command (generated from accept_edits_auto_allow rules)
/// Returns true if the command should be auto-allowed in acceptEdits mode.
pub fn is_file_editing_command(cmd: &CommandInfo) -> bool {
    let base_program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);

    // Quick check: is this a known file-editing program?
    if !FILE_EDITING_PROGRAMS.contains(base_program) {
        return false;
    }

    match base_program {
        "ast-grep" => cmd
            .args
            .iter()
            .any(|a| ["-U", "--update-all"].contains(&a.as_str())),
        "autopep8" => cmd
            .args
            .iter()
            .any(|a| ["-i", "--in-place"].contains(&a.as_str())),
        "biome" => {
            (cmd.args.first().is_some_and(|a| a == "check")
                && cmd
                    .args
                    .iter()
                    .any(|a| ["--write", "--fix", "--fix-unsafe"].contains(&a.as_str())))
                || (cmd.args.first().is_some_and(|a| a == "format")
                    && cmd.args.iter().any(|a| ["--write"].contains(&a.as_str())))
        }
        "black" => {
            // Bare rule: always file-editing
            true
        }
        "buf" => cmd.args.first().is_some_and(|a| a == "format"),
        "cargo" => {
            cmd.args.first().is_some_and(|a| a == "clippy")
                && cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str()))
        }
        "clang-format" => cmd.args.iter().any(|a| ["-i"].contains(&a.as_str())),
        "comby" => cmd
            .args
            .iter()
            .any(|a| ["-in-place", "-i"].contains(&a.as_str())),
        "dart" => cmd.args.first().is_some_and(|a| a == "format"),
        "dartfmt" => {
            // Bare rule: always file-editing
            true
        }
        "dos2unix" => {
            // Bare rule: always file-editing
            true
        }
        "elm-format" => {
            // Bare rule: always file-editing
            true
        }
        "eslint" => cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())),
        "gci" => cmd.args.iter().any(|a| ["write"].contains(&a.as_str())),
        "go" => cmd.args.first().is_some_and(|a| a == "fmt"),
        "gofmt" => cmd.args.iter().any(|a| ["-w"].contains(&a.as_str())),
        "goimports" => cmd.args.iter().any(|a| ["-w"].contains(&a.as_str())),
        "golangci-lint" => cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())),
        "grit" => cmd.args.first().is_some_and(|a| a == "apply"),
        "isort" => {
            // Bare rule: always file-editing
            true
        }
        "ktlint" => cmd
            .args
            .iter()
            .any(|a| ["-F", "--format"].contains(&a.as_str())),
        "mix" => cmd.args.first().is_some_and(|a| a == "format"),
        "mkdir" => {
            // Bare rule: always file-editing
            true
        }
        "perltidy" => cmd.args.iter().any(|a| ["-b"].contains(&a.as_str())),
        "prettier" => cmd
            .args
            .iter()
            .any(|a| ["--write", "-w"].contains(&a.as_str())),
        "rubocop" => cmd
            .args
            .iter()
            .any(|a| ["-a", "-A", "--auto-correct", "--autocorrect"].contains(&a.as_str())),
        "ruff" => {
            (cmd.args.first().is_some_and(|a| a == "check")
                && cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())))
                || cmd.args.first().is_some_and(|a| a == "format")
        }
        "rustfmt" => {
            // Bare rule: always file-editing
            true
        }
        "sad" => cmd.args.iter().any(|a| ["--commit"].contains(&a.as_str())),
        "scalafmt" => {
            // Bare rule: always file-editing
            true
        }
        "sd" => {
            // Bare rule: always file-editing
            true
        }
        "sed" => cmd
            .args
            .iter()
            .any(|a| ["-i", "--in-place"].contains(&a.as_str())),
        "semgrep" => cmd
            .args
            .iter()
            .any(|a| ["--autofix", "--fix"].contains(&a.as_str())),
        "sg" => cmd
            .args
            .iter()
            .any(|a| ["-U", "--update-all"].contains(&a.as_str())),
        "shfmt" => cmd.args.iter().any(|a| ["-w"].contains(&a.as_str())),
        "standardrb" => cmd
            .args
            .iter()
            .any(|a| ["-a", "-A", "--auto-correct", "--autocorrect"].contains(&a.as_str())),
        "stylelint" => cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())),
        "stylua" => {
            // Bare rule: always file-editing
            true
        }
        "swiftformat" => {
            // Bare rule: always file-editing
            true
        }
        "terraform" => cmd.args.first().is_some_and(|a| a == "fmt"),
        "tofu" => cmd.args.first().is_some_and(|a| a == "fmt"),
        "unix2dos" => {
            // Bare rule: always file-editing
            true
        }
        "yq" => cmd
            .args
            .iter()
            .any(|a| ["-i", "--inplace"].contains(&a.as_str())),
        _ => false,
    }
}

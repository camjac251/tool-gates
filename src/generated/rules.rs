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
        "b3sum",
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
        "dpkg-query",
        "du",
        "dust",
        "echo",
        "env",
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
        "glow",
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
        "jc",
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
        "mktemp",
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
        "pdfinfo",
        "pdftotext",
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
        "token-counter",
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
        "xxh128sum",
        "xxh32sum",
        "xxh64sum",
        "xxhsum",
        "yes",
        "yq",
        "z",
        "zcat",
        "zgrep",
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
        ("run download", "Downloading artifacts (writes to local filesystem)"),
        ("release download", "Downloading release assets (writes to local filesystem)"),
        ("gist clone", "Cloning gist (writes to local filesystem)"),
        ("issue create", "Creating issue"),
        ("issue close", "Closing issue"),
        ("issue reopen", "Reopening issue"),
        ("issue edit", "Editing issue"),
        ("issue comment", "Adding comment"),
        ("issue delete", "Deletes issue `<issue>` permanently. Irreversible; comments and reactions go with it. Prefer `close` for normal workflow."),
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
        ("pr merge", "Merges PR `<pr>` into the base branch. `--squash`/`--rebase` rewrite history; `--delete-branch` also deletes the source branch."),
        ("pr ready", "Marking PR ready"),
        ("pr review", "Submitting review"),
        ("pr checkout", "Checking out PR"),
        ("repo create", "Creating repository"),
        ("repo rename", "Renaming repository"),
        ("repo edit", "Editing repository"),
        ("repo fork", "Forking repository"),
        ("repo archive", "Archives the repository on GitHub. Becomes read-only: no new issues, PRs, comments, or pushes. Reversible via `repo unarchive`."),
        ("repo unarchive", "Unarchiving repository"),
        ("repo sync", "Syncing repository"),
        ("repo set-default", "Setting default repo"),
        ("release create", "Creating release"),
        ("release delete", "Deletes release `<release>` from GitHub. Removes release notes and uploaded assets; the underlying git tag stays unless `--cleanup-tag` is passed."),
        ("release edit", "Editing release"),
        ("release upload", "Uploading asset"),
        ("release delete-asset", "Deleting asset"),
        ("gist create", "Creating gist"),
        ("gist delete", "Deletes gist `<gist>` permanently. Irreversible; comments and revision history go with it."),
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
        ("codespace delete", "Deletes a codespace. Unsaved local changes inside the codespace are lost."),
        ("codespace edit", "Editing codespace"),
        ("codespace stop", "Stopping codespace"),
        ("codespace rebuild", "Rebuilding codespace"),
        ("cs create", "Creating codespace"),
        ("cs delete", "Deletes a codespace. Unsaved local changes inside the codespace are lost."),
        ("ssh-key add", "Adding SSH key"),
        ("ssh-key delete", "Removes an SSH key from the GitHub account. SSH access from any machine using that key will stop working."),
        ("gpg-key add", "Adding GPG key"),
        ("gpg-key delete", "Removes a GPG key from the GitHub account. Existing signed commits stay valid; future signatures with this key will not be marked verified."),
        ("config set", "Setting config"),
        ("config clear-cache", "Clearing cache"),
        ("secret set", "Setting secret"),
        ("secret delete", "Deletes an Actions/Codespaces/Dependabot secret. Future workflow runs that read this secret will fail until it is recreated."),
        ("variable set", "Sets an Actions variable for the repo, environment, or organization. Visible to future workflow runs."),
        ("variable delete", "Deletes an Actions variable. Future workflow runs that read this variable will see it as empty."),
        ("cache delete", "Deletes one or more GitHub Actions caches. Next workflow run that expects this cache will rebuild it from scratch."),
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
    ].into_iter().collect()
});

pub static GH_BLOCK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("repo delete", "Deletes the repository on GitHub. Irreversible: history, issues, PRs, releases, and forks-from-this-repo are removed. Blocked unconditionally."),
        ("auth logout", "Logs out the gh CLI from GitHub. The agent has no way to re-authenticate without user interaction. Blocked unconditionally."),
    ].into_iter().collect()
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
        ("gc", "Runs garbage collection in `.git`. Repacks objects and may prune unreachable commits older than the gc grace window."),
        ("prune", "Deletes unreachable objects from `.git`. Cannot be recovered without a backup or reflog entry still pointing at them."),
        ("config set", "Sets a git config value. `--local` scopes to this repo; `--global` affects all repos for the user."),
        ("config --add", "Adds a git config entry. `--local` for this repo, `--global` for user-wide."),
        ("config --unset", "Removes a git config entry. Permanent for the chosen scope."),
        ("stash drop", "Drops a stash permanently. Run `git stash list` first to confirm the index; cannot be undone."),
        ("stash pop", "Applies the top stash and removes it. Use `git stash apply` if you want to keep the stash entry."),
        ("stash clear", "Clears ALL stashes permanently. List with `git stash list` first; cannot be undone."),
        ("stash push", "Saves working-tree changes to a new stash entry."),
        ("stash apply", "Applies a stash entry without removing it from the stash list."),
        ("worktree add", "Creates a new linked worktree checkout. Writes a new directory and registers it in `.git/worktrees/`."),
        ("worktree remove", "Removes a worktree directory. Refuses if it has uncommitted changes unless `--force`."),
        ("worktree prune", "Prunes stale worktree references that no longer point to a real directory."),
        ("submodule foreach", "`git submodule foreach` runs an arbitrary shell command per submodule. Treat the command as if invoked directly."),
        ("submodule init", "Registers submodules from `.gitmodules` into the local repo config. Does not fetch content; pair with `submodule update`."),
        ("submodule update", "Fetches and checks out submodule commits recorded in the superproject. Can overwrite local submodule edits unless `--merge`/`--rebase` is set."),
        ("submodule add", "Adds a new submodule entry to `.gitmodules` and clones the remote repo into the tree."),
        ("submodule deinit", "Unregisters submodules and clears their working tree. Use `--force` to drop uncommitted submodule changes."),
        ("remote add", "Registers a new remote URL under the given name. Subsequent fetches/pushes will trust this endpoint."),
        ("remote remove", "Removes a remote and its tracking refs from this repo. Does not affect the remote server."),
        ("remote rename", "Renames a remote and rewrites tracking-branch refs to use the new name."),
        ("remote set-url", "Changes the URL of an existing remote. Future fetches/pushes will hit the new endpoint."),
        ("commit", "Records staged changes as a new commit on the current branch."),
        ("push", "Publishes local commits to a remote. Inspect `git log @{u}..` first to see what would be sent."),
        ("pull", "Fetches and integrates remote changes into the current branch. Use `--rebase` to avoid merge commits."),
        ("merge", "Merges another branch into the current one. Can produce conflicts; abort with `git merge --abort`."),
        ("rebase", "Rebasing. Non-interactive only; interactive (`-i`) hangs the agent. Use `git revise --autosquash` for fixups."),
        ("checkout", "Switches branches or restores files in the working tree. Uncommitted edits in affected files may be lost."),
        ("switch", "Switches the working tree to another branch. Refuses if local edits would conflict unless `--discard-changes` is set."),
        ("reset", "Moves HEAD and optionally the index/working tree. `--soft` keeps changes staged, `--mixed` (default) unstages, `--hard` discards."),
        ("restore", "Restores files in the working tree from the index or a commit. Overwrites uncommitted edits in the targeted paths."),
        ("clean", "Cleans the working tree. Preview with `-n` first if unsure what would be deleted."),
        ("cherry-pick", "Replays the listed commits on the current branch. May produce conflicts; abort with `git cherry-pick --abort`."),
        ("revert", "Creates a new commit that undoes the listed commits. Preserves history; does not rewrite it."),
        ("am", "Applies a mailbox patch series as commits. Stops on conflict; resolve and `git am --continue`."),
        ("apply", "Applies a patch to the working tree (no commit created). Use `--check` to preview without writing."),
        ("format-patch", "Writes one `.patch` file per commit in the specified range. Output goes to the working directory."),
        ("init", "Creates a new git repository in the current directory. Writes a `.git/` directory."),
        ("clone", "Clones a remote repository into a new directory. Network operation; size depends on remote history."),
        ("fetch", "Downloads refs and objects from a remote. Does not modify the working tree or current branch."),
        ("mv", "Moves or renames a tracked file and stages the rename in one step."),
        ("rm", "Removes a tracked file from the working tree and stages the deletion. `--cached` keeps the file on disk."),
        ("bisect", "Starts a binary-search session over commit history. Mutates HEAD across iterations; end with `git bisect reset`."),
        ("filter-branch", "Rewrites commit history. Safer alternatives: `git revise --autosquash` for fixups, `git absorb` for auto-folding edits. `git-filter-repo` is the maintained replacement for filter-branch."),
        ("filter-repo", "Rewrites commit history. Refuses to run on non-fresh clones; use `--force` only with intent."),
        ("notes", "Adds, edits, or removes notes attached to commits. Stored in `refs/notes/*`; not shown in default `git log`."),
        ("bundle", "Creates or unpacks a git bundle file (offline-transportable pack of refs and objects)."),
        ("maintenance", "Runs repo maintenance tasks (gc, commit-graph, prefetch, loose-objects). Modifies `.git/` in the background."),
        ("sparse-checkout", "Modifies sparse-checkout config. Changes which files are materialized in the working tree."),
        ("worktree", "Worktree operation. See `git worktree --help` for subcommand-specific risk."),
    ].into_iter().collect()
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
        return Some(GateResult::ask(
            "Force push overwrites upstream history. Safer: `--force-with-lease` fails if the remote moved.",
        ));
    }
    if subcmd_single == "reset" && cmd.args.iter().any(|a| ["--hard"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Hard reset discards uncommitted changes in the working tree and index. Safer: `git stash` first, or `git reset --soft` to keep changes staged.",
        ));
    }
    if subcmd_single == "clean"
        && cmd
            .args
            .iter()
            .any(|a| ["-fd", "-fdx", "-f"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Permanently deletes untracked files. Preview with `-n` (dry run) first; deletions cannot be undone.",
        ));
    }
    if subcmd_single == "checkout" && cmd.args.iter().any(|a| ["-b", "-B"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Creates a new branch and switches to it. `-B` resets an existing branch of the same name to the start point.",
        ));
    }
    if subcmd_single == "checkout" && cmd.args.iter().any(|a| ["--"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Discards uncommitted changes in the listed paths. Cannot be undone.",
        ));
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
        return Some(GateResult::ask(
            "Creates a tag pointing at the named commit (HEAD by default). Local only until `git push --tags`.",
        ));
    }
    if subcmd_single == "tag"
        && cmd
            .args
            .iter()
            .any(|a| ["-d", "--delete"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Deletes a local tag. Use `git push --delete <remote> <tag>` separately to delete it on the remote.",
        ));
    }
    if subcmd_single == "tag"
        && cmd
            .args
            .iter()
            .any(|a| ["-f", "--force"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Force-replacing a tag breaks anyone who already pulled it. Confirm no downstream consumers.",
        ));
    }
    if subcmd_single == "branch"
        && cmd
            .args
            .iter()
            .any(|a| ["-d", "-D", "--delete"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Deleting a branch. Prefer `-d` (refuses if unmerged) over `-D` (force) when possible.",
        ));
    }
    if subcmd_single == "branch"
        && cmd
            .args
            .iter()
            .any(|a| ["-m", "-M", "--move"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Renames a branch. `-M` forces the rename even if it would overwrite an existing branch name.",
        ));
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
    [
        ("iam delete-user", "Blocked: `aws iam delete-user` removes an IAM identity. Detach policies and rotate access keys via individual commands instead."),
    ].into_iter().collect()
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
        return Some(GateResult::block(
            "aws: Blocked: `aws organizations delete-*` removes organization-level entities (accounts, OUs, policies). Effects span the whole org and are hard to reverse.",
        ));
    }

    // Check ask rules with flag/prefix conditions
    if cmd.args.get(1).is_some_and(|a| a.starts_with("create")) {
        return Some(GateResult::ask(
            "aws: AWS create operation: provisions a new resource in the account. Verify region, profile, and resource type; provisioning may incur cost.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("delete")) {
        return Some(GateResult::ask(
            "aws: AWS delete operation. Verify region, profile, and resource ID before approving; most deletions cannot be reversed.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("put")) {
        return Some(GateResult::ask(
            "aws: AWS put operation: writes or overwrites a resource (object, item, policy, parameter). Existing values are replaced; previous content may be lost.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("update")) {
        return Some(GateResult::ask(
            "aws: AWS update operation: changes the configuration of an existing resource. Effect is immediate; review the diff first.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("modify")) {
        return Some(GateResult::ask(
            "aws: AWS modify operation: changes attributes of a running resource (instance type, security group, parameter). May restart or interrupt the resource.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("remove")) {
        return Some(GateResult::ask(
            "aws: AWS remove operation: removes attached items (tags, permissions, members). Effect is immediate.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("run")) {
        return Some(GateResult::ask(
            "aws: AWS run operation: launches resources such as EC2 instances or task definitions. Billing starts when they reach running state.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("start")) {
        return Some(GateResult::ask(
            "aws: AWS start operation: starts a stopped resource (instance, DB, pipeline). Billing typically resumes once running.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("stop")) {
        return Some(GateResult::ask(
            "aws: AWS stop operation: halts a running resource. Connected clients drop; storage bills usually continue.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("terminate")) {
        return Some(GateResult::ask(
            "aws: AWS terminate operation: permanently destroys the resource (instance, workflow execution). Attached ephemeral storage is lost.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("reboot")) {
        return Some(GateResult::ask(
            "aws: AWS reboot operation: restarts a running resource (instance, cache cluster, DB). Causes downtime during the reboot window.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("attach")) {
        return Some(GateResult::ask(
            "aws: AWS attach operation: connects one resource to another (volume to instance, policy to role, gateway to VPC). Live traffic/state may shift.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("detach")) {
        return Some(GateResult::ask(
            "aws: AWS detach operation: disconnects an attached resource (volume, policy, network interface). The detached side loses that access.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("associate")) {
        return Some(GateResult::ask(
            "aws: AWS associate operation: links resources (route table to subnet, address to instance, IAM identity to provider). May reroute live traffic.",
        ));
    }
    if cmd
        .args
        .get(1)
        .is_some_and(|a| a.starts_with("disassociate"))
    {
        return Some(GateResult::ask(
            "aws: AWS disassociate operation: unlinks resources (address from instance, route table from subnet). May break in-flight traffic.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("enable")) {
        return Some(GateResult::ask(
            "aws: AWS enable operation: turns on a feature or service (logging, MFA, region, security control). Effect is immediate.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("disable")) {
        return Some(GateResult::ask(
            "aws: AWS disable operation: turns off a feature or service (logging, MFA, security control). Coverage drops immediately.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("register")) {
        return Some(GateResult::ask(
            "aws: AWS register operation: registers a target with a service (task definition, target with load balancer, domain). Becomes live to that service.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("deregister")) {
        return Some(GateResult::ask(
            "aws: AWS deregister operation: removes a registered target (from load balancer, task definition). The target stops receiving traffic.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("invoke")) {
        return Some(GateResult::ask(
            "aws: AWS invoke operation: executes a function or state machine (Lambda, Step Functions). Side effects run in the cloud and may incur cost.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("publish")) {
        return Some(GateResult::ask(
            "aws: AWS publish operation: publishes a message, version, or layer (SNS, Lambda version, layer version). Subscribers/consumers see it immediately.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("send")) {
        return Some(GateResult::ask(
            "aws: AWS send operation: dispatches a message or signal (SQS, SES, command to instance). Delivery is real-time and may cost per message.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("tag")) {
        return Some(GateResult::ask(
            "aws: AWS tag operation: adds tags to a resource. Tags can drive billing allocation and IAM conditions; pick keys/values intentionally.",
        ));
    }
    if cmd.args.get(1).is_some_and(|a| a.starts_with("untag")) {
        return Some(GateResult::ask(
            "aws: AWS untag operation: removes tags from a resource. Tag-based IAM policies and cost allocation depending on those tags will stop applying.",
        ));
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
        ("container clusters get-credentials", "Updating kubeconfig (writes to `~/.kube/config`)"),
        ("compute instances create", "GCE create: provisions a new VM in the project. Billing starts when it boots; verify zone, machine type, and network."),
        ("compute instances delete", "GCE compute delete: terminates the VM. Persistent disks may or may not be deleted depending on flags."),
        ("compute instances start", "GCE start: boots a stopped VM. Compute billing resumes once the instance is running."),
        ("compute instances stop", "GCE stop: shuts the VM down. Connections drop; persistent disks still bill while stopped."),
        ("compute instances reset", "GCE reset: hard-reboots the VM without a clean shutdown. In-memory state and unflushed disk writes are lost."),
        ("container clusters create", "GKE create: provisions a new Kubernetes cluster. Control plane and node pools begin billing immediately."),
        ("container clusters delete", "GKE delete: tears down the cluster including all workloads. Cannot be reversed."),
        ("container clusters resize", "GKE resize: changes node pool size. Scaling down evicts pods from removed nodes; scaling up adds nodes that begin billing."),
        ("container clusters upgrade", "GKE upgrade: upgrades the control plane or node pool version. Workloads get rescheduled during node rollouts; cannot be downgraded mid-flight."),
        ("storage cp", "GCS copy: writes objects into a bucket. May overwrite existing objects at the same key."),
        ("storage mv", "GCS move: copies then deletes the source. Failure mid-operation can leave partial state at the destination."),
        ("storage rm", "GCS delete: removes objects from a bucket. Recursive (`-r`) on a prefix deletes every matching object; recovery requires object versioning."),
        ("functions deploy", "Cloud Functions deploy: uploads source and publishes a new revision. Traffic shifts to the new version once deployment succeeds."),
        ("functions delete", "Cloud Functions delete: removes the function. Triggers stop firing immediately; callers get errors until recreated."),
        ("run deploy", "Cloud Run deploy: builds/pulls the image and rolls out a new revision. Traffic shifts to it per the service's traffic policy."),
        ("run services delete", "Cloud Run delete: removes the service. Live traffic returns 404 until redeploy."),
        ("sql instances create", "Cloud SQL create: provisions a managed database instance. Billing starts at create time; tier and storage choices are sticky."),
        ("sql instances delete", "Cloud SQL delete: removes the database instance and its data. Restore requires a prior backup; otherwise data is gone."),
        ("sql instances patch", "Cloud SQL patch: changes instance settings (tier, flags, maintenance, network). Some changes restart the instance."),
        ("secrets create", "Secret Manager create: creates a new secret container. Initial payload value (if provided) lands in Cloud audit logs at IAM read."),
        ("secrets delete", "Secret Manager delete: removes the secret and all its versions. Consumers that read it will start failing immediately."),
        ("projects create", "GCP project create: provisions a new project under your org/billing. Project IDs are globally unique and cannot be reused."),
        ("projects delete", "GCP project delete: schedules the project for deletion (30-day grace). All resources go offline immediately."),
    ].into_iter().collect()
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
        "workspace show",
    ]
    .into_iter()
    .collect()
});

pub static TERRAFORM_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("test", "Terraform test: runs `.tftest.hcl` cases. With `command = apply` (default), test cases create real infrastructure for the duration of the run."),
        ("console", "Terraform console: interactive REPL against the current state. Evaluates expressions only, but reads state from the configured backend."),
        ("force-unlock", "Terraform force-unlock removes a stuck state lock. Confirm no other apply is in progress; concurrent applies corrupt state."),
        ("apply", "Terraform apply: applies planned changes to real infrastructure. Run `terraform plan` first and review the diff."),
        ("destroy", "Terraform destroy: tears down resources tracked by this state. Use `-target` to scope; cannot be undone."),
        ("import", "Terraform import: brings an existing real resource under terraform management. Verify the address matches your config."),
        ("taint", "Terraform taint: marks a resource for replacement on the next apply. The next `apply` will destroy and recreate it."),
        ("untaint", "Terraform untaint: clears the tainted mark from a resource so the next apply does not replace it."),
        ("init", "Terraform init: downloads providers/modules and configures the backend. Writes `.terraform/` and `.terraform.lock.hcl`."),
        ("fmt", "Terraform fmt: rewrites `.tf` files in place to canonical style. Use `-check` to verify without modifying."),
        ("state mv", "Terraform state mv: renames or reparents resources in state. Validate addresses; mistakes leave resources orphaned."),
        ("state rm", "Terraform state rm: drops a resource from state without destroying it in the cloud. The resource becomes unmanaged."),
        ("state push", "Terraform state push: overwrites remote state with local. Take a backup of remote state first."),
        ("state pull", "Terraform state pull: downloads the current remote state to stdout. Read-only on remote state, but exposes sensitive values."),
        ("workspace new", "Terraform workspace new: creates a new workspace with its own state file. Subsequent commands run against it until switched."),
        ("workspace delete", "Terraform workspace delete: removes the workspace and its state file. State cannot be recovered after deletion."),
        ("workspace select", "Terraform workspace select: switches the active workspace. Subsequent plan/apply runs target the selected workspace's state."),
    ].into_iter().collect()
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
        "diff",
        "kustomize",
        "wait",
    ]
    .into_iter()
    .collect()
});

pub static KUBECTL_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("debug", "kubectl debug: attaches an ephemeral debug container to a running pod or node. The debug container runs with the target's namespace and may have elevated access."),
        ("apply", "kubectl apply: creates or updates resources from a manifest in the current context/namespace. Drift between cluster and file is reconciled toward the file."),
        ("create", "kubectl create: imperatively creates a resource in the current context/namespace. Fails if the resource already exists."),
        ("delete", "kubectl delete: removes the resource from the cluster. Verify namespace/context; many resources cascade-delete dependents."),
        ("edit", "kubectl edit: opens the live resource in $EDITOR and applies on save. Changes go straight to the cluster; no diff review."),
        ("patch", "kubectl patch: applies a strategic/JSON/merge patch to a live resource. Effect is immediate; rolling updates can trigger pod restarts."),
        ("replace", "kubectl replace: replaces a live resource entirely with the manifest. Fields absent from the file are dropped; `--force` deletes and recreates."),
        ("scale", "kubectl scale: changes the replica count on a Deployment/StatefulSet/ReplicaSet. Scaling to 0 stops the workload."),
        ("rollout", "kubectl rollout: triggers, pauses, resumes, undoes, or restarts a Deployment/DaemonSet/StatefulSet rollout. Pods get replaced per the strategy."),
        ("expose", "kubectl expose: creates a Service in front of a workload. With type=LoadBalancer it provisions a cloud LB; type=NodePort opens a node port."),
        ("run", "kubectl run: creates a pod in the current namespace from an image. Useful for one-off shells/jobs; leaves a pod behind unless `--rm` is set."),
        ("exec", "kubectl exec: runs a command inside a running container. Side effects (writes, signals) happen in the live pod."),
        ("cp", "kubectl cp: copies files between local FS and a pod via `tar` in the container. Requires `tar` in the container image."),
        ("port-forward", "kubectl port-forward: tunnels a local port to a pod/service. Anyone on the local host can reach the forwarded target while running."),
        ("label", "kubectl label: adds, updates, or removes labels on a resource. Labels drive selectors (Services, NetworkPolicies, scheduling); changes can shift routing."),
        ("annotate", "kubectl annotate: adds, updates, or removes annotations on a resource. Annotations can configure controllers (ingress, autoscaler, sidecars)."),
        ("taint", "kubectl taint: adds a taint to a node so non-tolerating pods avoid it. With `NoExecute`, existing non-tolerating pods are evicted."),
        ("drain", "kubectl drain: cordons the node and evicts its pods to other nodes. Confirm replicas/replacements exist before approving."),
        ("cordon", "kubectl cordon: marks a node unschedulable. Existing pods stay; new pods land elsewhere."),
        ("uncordon", "kubectl uncordon: marks a node schedulable again. The scheduler resumes placing new pods on it."),
        ("config set-context", "kubectl config set-context: writes a context entry to `~/.kube/config`. Sets cluster, user, and default namespace for that context."),
        ("config use-context", "kubectl config use-context: switches the current context in `~/.kube/config`. Subsequent kubectl commands target the new cluster/namespace."),
        ("config set-cluster", "kubectl config set-cluster: writes a cluster entry (server URL, CA data) to `~/.kube/config`. Misconfigured CA bypasses TLS verification."),
        ("config set-credentials", "kubectl config set-credentials: writes auth data (token, cert, exec plugin) to `~/.kube/config`. Anyone with read access to the file gets those credentials."),
        ("config delete-context", "kubectl config delete-context: removes a context from `~/.kube/config`. The cluster and user entries it referenced are left intact."),
        ("config delete-cluster", "kubectl config delete-cluster: removes a cluster entry from `~/.kube/config`. Contexts that referenced it stop working."),
    ].into_iter().collect()
});

pub static KUBECTL_BLOCK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("delete namespace kube-system", "Refusing to delete the `kube-system` namespace. It hosts core cluster services; deleting it breaks the cluster."),
        ("delete ns kube-system", "Refusing to delete the `kube-system` namespace. It hosts core cluster services; deleting it breaks the cluster."),
    ].into_iter().collect()
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
        "buildx ls",
        "buildx inspect",
        "buildx version",
        "scout quickview",
        "scout cves",
        "scout recommendations",
        "scout compare",
        "context ls",
        "context list",
        "context show",
        "context inspect",
        "manifest inspect",
        "image ls",
        "image list",
        "image inspect",
        "image history",
        "container ls",
        "container list",
        "container inspect",
        "container logs",
        "container top",
        "container stats",
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
        ("buildx build", "Docker buildx build: builds an image (optionally multi-arch). Pulls base images and may push if `--push` is set."),
        ("buildx create", "Docker buildx create: creates a new builder instance (may spin up a container or remote driver). Subsequent builds use it."),
        ("buildx rm", "Docker buildx rm: removes a builder instance and its cache. In-progress builds against it fail."),
        ("buildx use", "Docker buildx use: sets the active builder. Subsequent `docker buildx build` calls use the selected builder."),
        ("buildx stop", "Docker buildx stop: stops a running builder instance. In-progress builds on it are interrupted."),
        ("buildx prune", "Docker buildx prune: deletes unused build cache. Frees disk; next builds are slower until cache rewarms."),
        ("scout enroll", "Docker Scout enroll: opts the organization into Docker Scout vulnerability scanning. Image data is uploaded to Docker's service."),
        ("context create", "Docker context create: registers a new daemon endpoint in the Docker config. Subsequent commands can target it."),
        ("context rm", "Docker context rm: removes a context from the Docker config. If it was active, the default context becomes active."),
        ("context use", "Docker context use: switches the active daemon endpoint. Subsequent docker commands target the new daemon (potentially remote)."),
        ("manifest create", "Docker manifest create: builds a local multi-arch manifest list referencing existing image digests. Not yet pushed to a registry."),
        ("manifest push", "Docker manifest push: publishes the manifest list to the registry. Consumers of that tag will pull the new manifest immediately."),
        ("manifest annotate", "Docker manifest annotate: edits a local manifest list (os/arch/variant). Push is a separate step."),
        ("image rm", "Docker image rm: removes a local image (and its layers if unreferenced). Containers using that image still run."),
        ("image prune", "Docker image prune: deletes dangling (or with `-a`, all unused) local images. Reclaims disk; can be expensive to repull."),
        ("image tag", "Docker image tag: creates a new ref pointing at an existing image. Local-only until pushed."),
        ("image push", "Docker image push: uploads the image (and layers) to the registry under the given ref. Overwrites the tag for everyone consuming it."),
        ("image pull", "Docker image pull: downloads an image from a registry. Network/disk usage; verify the ref is the intended source."),
        ("container rm", "Docker container rm: removes a stopped container (with `-f`, also force-kills a running one). Anonymous volumes are removed only with `-v`."),
        ("container start", "Docker container start: starts an existing stopped container. Bound ports and volumes from the original `run` reapply."),
        ("container stop", "Docker container stop: sends SIGTERM then SIGKILL after the grace period. In-flight requests to the container drop."),
        ("container kill", "Docker container kill: sends a signal (SIGKILL by default) directly. No graceful shutdown; in-flight work is lost."),
        ("container prune", "Docker container prune: deletes all stopped containers. Their writable layers and anonymous state are gone."),
        ("compose up", "Compose up: starts the services in the current compose file. Builds/pulls images as needed; with `-d` runs detached."),
        ("compose down", "Compose down: stops and removes containers, networks, and (with `-v`) volumes for the project. Persistent state in named volumes survives unless `-v` is set."),
        ("compose start", "Compose start: starts already-created service containers. Does not create or rebuild."),
        ("compose stop", "Compose stop: stops running service containers but leaves them in place. In-flight requests drop."),
        ("compose restart", "Compose restart: restarts service containers without recreating them. Brief downtime per service."),
        ("compose build", "Compose build: builds (or rebuilds) the services' images per the compose file. Local-only until pushed."),
        ("compose pull", "Compose pull: pulls the service images from their registries. Disk/network usage."),
        ("compose push", "Compose push: pushes the service images to their registries. Overwrites the tags for anyone consuming them."),
        ("compose exec", "Compose exec: runs a command inside a running service container. Side effects (writes, signals) happen in that live container."),
        ("compose run", "Compose run: spins up a one-off service container with the given command. Leaves a stopped container behind unless `--rm` is set."),
        ("compose rm", "Compose rm: removes stopped service containers (with `-s` it also stops them first). Anonymous volumes go with `-v`."),
        ("compose create", "Compose create: creates service containers without starting them. Useful before a separate `start`."),
        ("compose kill", "Compose kill: sends SIGKILL to running service containers. No graceful shutdown."),
        ("compose pause", "Compose pause: freezes all processes in the service containers via cgroups. Connections hang until unpaused."),
        ("compose unpause", "Compose unpause: resumes previously-paused service containers."),
        ("run", "Docker run: creates and starts a new container from an image. Honours `-v` mounts, port publishes, and `--privileged`; verify those before approving."),
        ("exec", "Docker exec: runs a command inside an already-running container. Side effects happen in that live container."),
        ("build", "Docker build: builds an image from a Dockerfile. Pulls base images; local-only until pushed."),
        ("push", "Docker push: uploads an image to the registry under the given ref. Overwrites the tag for everyone consuming it."),
        ("pull", "Docker pull: downloads an image from a registry. Network/disk usage; verify the ref."),
        ("rm", "Docker rm: removes a stopped container (with `-f`, also force-kills a running one). Anonymous volumes go with `-v`."),
        ("rmi", "Docker rmi: removes a local image. Containers using it still run; layers go when no ref remains."),
        ("kill", "Docker kill: sends a signal (SIGKILL by default) directly to the container PID 1. No graceful shutdown."),
        ("stop", "Docker stop: sends SIGTERM then SIGKILL after the grace period. In-flight requests drop."),
        ("start", "Docker start: starts an existing stopped container. Original `run` config (ports, mounts) reapplies."),
        ("restart", "Docker restart: stops and starts the container. Brief downtime; existing config reapplies."),
        ("pause", "Docker pause: freezes all processes in the container via cgroups. Connections hang until unpaused."),
        ("unpause", "Docker unpause: resumes a previously-paused container."),
        ("tag", "Docker tag: creates a new ref pointing at an existing image. Local-only until pushed."),
        ("commit", "Docker commit: creates a new image from a container's writable layer. Image is not reproducible from a Dockerfile."),
        ("cp", "Docker cp: copies files between the local FS and a container. Overwrites destination paths."),
        ("login", "Docker login: writes registry credentials to `~/.docker/config.json` (or the configured credential helper). Anyone with read access to the file gets those credentials."),
        ("logout", "Docker logout: removes registry credentials from the Docker config. Subsequent pulls/pushes to that registry need to re-auth."),
        ("network create", "Docker network create: creates a user-defined network. Containers can be attached and discover each other by name."),
        ("network rm", "Docker network rm: removes a network. Fails if containers are still attached; otherwise their inter-container DNS breaks."),
        ("network connect", "Docker network connect: attaches a running container to an additional network. Gives it new addresses and DNS visibility."),
        ("network disconnect", "Docker network disconnect: detaches a container from a network. Existing connections on that network drop."),
        ("volume create", "Docker volume create: creates a named volume managed by the engine. Persists across container recreates."),
        ("volume rm", "Docker volume rm: removes a named volume and its data. Fails if a container still references it; otherwise the data is gone."),
        ("system prune", "Docker system prune: deletes stopped containers, unused networks, dangling images, and build cache (with `-a --volumes` also more). Reclaims disk; can be expensive to rebuild."),
    ].into_iter().collect()
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
        ("run", "Podman run: creates and starts a new container from an image. Honours `-v` mounts and port publishes; verify those before approving."),
        ("exec", "Podman exec: runs a command inside an already-running container. Side effects happen in that live container."),
        ("build", "Podman build: builds an image from a Containerfile/Dockerfile. Pulls base images; local-only until pushed."),
        ("push", "Podman push: uploads an image to the registry under the given ref. Overwrites the tag for consumers."),
        ("pull", "Podman pull: downloads an image from a registry. Network/disk usage; verify the ref."),
        ("rm", "Podman rm: removes a stopped container (with `-f`, also force-kills a running one). Anonymous volumes go with `-v`."),
        ("rmi", "Podman rmi: removes a local image. Containers using it still run; layers go when no ref remains."),
        ("kill", "Podman kill: sends a signal (SIGKILL by default) to the container PID 1. No graceful shutdown."),
        ("stop", "Podman stop: sends SIGTERM then SIGKILL after the grace period. In-flight requests drop."),
        ("start", "Podman start: starts an existing stopped container. Original `run` config (ports, mounts) reapplies."),
        ("restart", "Podman restart: stops and starts the container. Brief downtime; existing config reapplies."),
        ("pause", "Podman pause: freezes all processes in the container via cgroups. Connections hang until unpaused."),
        ("unpause", "Podman unpause: resumes a previously-paused container."),
        ("tag", "Podman tag: creates a new ref pointing at an existing image. Local-only until pushed."),
        ("commit", "Podman commit: creates a new image from a container's writable layer. Image is not reproducible from a Containerfile."),
        ("cp", "Podman cp: copies files between the local FS and a container. Overwrites destination paths."),
        ("login", "Podman login: writes registry credentials to the auth store. Anyone with read access to the file gets those credentials."),
        ("logout", "Podman logout: removes registry credentials from the auth store. Subsequent pulls/pushes need to re-auth."),
        ("create", "Podman create: creates a container without starting it. Useful before a separate `start`."),
        ("pod", "Podman pod: pod-level operation (create/start/stop/rm). Affects all containers in the pod at once."),
        ("generate", "Podman generate: emits Kubernetes/systemd config from existing containers or pods to stdout (or a file). May write to disk depending on flags."),
        ("play", "Podman play: creates pods and containers from a Kubernetes YAML manifest. Pulls images and starts workloads locally."),
    ].into_iter().collect()
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
        ("up", "Compose up: starts the services in the current compose file. Builds/pulls images as needed; with `-d` runs detached."),
        ("down", "Compose down: stops and removes containers, networks, and (with `-v`) volumes for the project. Named-volume data survives unless `-v` is set."),
        ("start", "Compose start: starts already-created service containers. Does not create or rebuild."),
        ("stop", "Compose stop: stops running service containers but leaves them in place. In-flight requests drop."),
        ("restart", "Compose restart: restarts service containers without recreating them. Brief downtime per service."),
        ("pause", "Compose pause: freezes all processes in the service containers via cgroups. Connections hang until unpaused."),
        ("unpause", "Compose unpause: resumes previously-paused service containers."),
        ("build", "Compose build: builds (or rebuilds) the services' images per the compose file. Local-only until pushed."),
        ("push", "Compose push: pushes the service images to their registries. Overwrites the tags for consumers."),
        ("pull", "Compose pull: pulls the service images from their registries. Disk/network usage."),
        ("rm", "Compose rm: removes stopped service containers (with `-s` it also stops them first). Anonymous volumes go with `-v`."),
        ("kill", "Compose kill: sends SIGKILL to running service containers. No graceful shutdown."),
        ("exec", "Compose exec: runs a command inside a running service container. Side effects happen in that live container."),
        ("run", "Compose run: spins up a one-off service container with the given command. Leaves a stopped container behind unless `--rm` is set."),
        ("create", "Compose create: creates service containers without starting them. Useful before a separate `start`."),
    ].into_iter().collect()
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
        ("repo add", "Helm repo add: registers a chart repository in the local Helm config. Subsequent installs can pull charts from it."),
        ("repo remove", "Helm repo remove: removes a chart repository from the local Helm config. Existing releases keep running."),
        ("repo update", "Helm repo update: refreshes the local index for all repos. Read-only on clusters; updates local cache files."),
        ("install", "Helm install: deploys a chart as a new release into the current kube context/namespace. Creates the resources defined in the chart."),
        ("upgrade", "Helm upgrade: applies a new chart version or values to an existing release. Workloads may roll; use `--atomic` to auto-rollback on failure."),
        ("uninstall", "Helm uninstall: removes a release and all its Kubernetes resources from the cluster. Persistent volumes may be retained per chart settings."),
        ("rollback", "Helm rollback: rolls a release back to a previous revision. Workloads roll to match the earlier manifests."),
        ("delete", "Helm delete: removes a release (alias for uninstall in Helm 3). The release's Kubernetes resources are deleted."),
        ("push", "Helm push: uploads a packaged chart to an OCI registry. Overwrites the chart version for consumers of that ref."),
        ("package", "Helm package: bundles a chart directory into a `.tgz`. Local-only until pushed."),
    ].into_iter().collect()
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
        ("up", "Pulumi up: applies the current program to the selected stack, creating/updating/deleting cloud resources. Run `pulumi preview` first."),
        ("destroy", "Pulumi destroy: tears down every resource tracked by the selected stack. Cannot be undone without recreating from code."),
        ("refresh", "Pulumi refresh: reconciles state with the real cloud, updating the state file to match what is actually deployed."),
        ("import", "Pulumi import: brings an existing cloud resource under Pulumi management and emits code for it. Verify the resource address matches the program."),
        ("cancel", "Pulumi cancel: forcibly cancels an in-progress update on the stack. Partial state on the cloud side may not match the state file."),
        ("new", "Pulumi new: scaffolds a new project (and stack) in the current directory. Writes program files and `Pulumi.yaml`."),
        ("stack init", "Pulumi stack init: creates a new stack under the current project. The stack starts empty until `pulumi up` runs."),
        ("stack rm", "Pulumi stack rm: removes the stack's state and config. Use `--force` only after `pulumi destroy`; otherwise cloud resources are orphaned."),
        ("stack select", "Pulumi stack select: switches the active stack. Subsequent `up`/`destroy`/`config` commands target the selected stack."),
        ("config set", "Pulumi config set: writes a config value (optionally encrypted with `--secret`) into the stack's config file."),
        ("config rm", "Pulumi config rm: removes a config key from the stack. Programs that read it will fall back to defaults or error."),
    ].into_iter().collect()
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
        ("link", "Creates a global symlink to this package and links it into node_modules. Modifies the global npm prefix; can shadow real installs of `<package>` system-wide."),
        ("unlink", "Removes the global symlink created by `npm link`. Affects every project that consumed the linked package."),
        ("publish", "Publishes the package to its registry. Public publish is irreversible: the version number cannot be reused."),
        ("unpublish", "Removes a published version from the registry. Public unpublish is restricted by npm policy and can break downstream consumers."),
        ("deprecate", "Marks a published version as deprecated on the registry. Shows a warning to every future install of that version."),
        ("init", "Initializes a new package in the current directory by writing `package.json`. With `npm init <initializer>` it runs an arbitrary `create-<initializer>` package."),
        ("create", "Runs a `create-<name>` package to scaffold a project, downloading it if missing. Same trust boundary as `curl | bash` for untrusted initializers."),
        ("exec", "Runs an arbitrary command through the package manager (downloads the package if missing). Same trust boundary as `curl | bash` for untrusted packages."),
        ("npx", "Runs an arbitrary command through `npx` (downloads the package if missing). Same trust boundary as `curl | bash` for untrusted packages."),
        ("prune", "Removes packages from `node_modules` that are not listed in `package.json`."),
        ("dedupe", "Rewrites `node_modules` and `package-lock.json` to reduce duplication. Can change resolved versions."),
        ("shrinkwrap", "Writes `npm-shrinkwrap.json` to lock the dependency tree for publishing."),
        ("cache", "Mutates the npm cache (verify, clean, add). `npm cache clean --force` wipes all cached tarballs and metadata."),
        ("pack", "Builds a tarball of the package as it would be published. Writes a `.tgz` file to the cwd."),
        ("set", "Sets an npm config key. Default scope is the user-level `.npmrc`; `--global` writes to the global prefix."),
    ].into_iter().collect()
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
        ("exec", "Runs an arbitrary command through the package manager (downloads the package if missing). Same trust boundary as `curl | bash` for untrusted packages."),
        ("install", "Installing packages"),
        ("i", "Installing packages"),
        ("add", "Adding packages"),
        ("remove", "Removing packages"),
        ("rm", "Removing packages"),
        ("uninstall", "Removing packages"),
        ("update", "Updating packages"),
        ("up", "Updating packages"),
        ("link", "Creates a global symlink and links the package into node_modules. Modifies the global pnpm store and can shadow real installs of `<package>`."),
        ("unlink", "Removes the global symlink created by `pnpm link`. Affects every project that consumed the linked package."),
        ("publish", "Publishes the package to its registry. Public publish is irreversible: the version number cannot be reused."),
        ("init", "Initializes a new package in the current directory by writing `package.json`."),
        ("create", "Runs a `create-<name>` package to scaffold a project, downloading it if missing. Same trust boundary as `curl | bash` for untrusted initializers."),
        ("dlx", "Runs an arbitrary command through the package manager (downloads the package if missing). Same trust boundary as `curl | bash` for untrusted packages."),
        ("prune", "Removes packages from `node_modules` and the pnpm store that are not listed in `package.json`."),
        ("store", "Mutates the shared pnpm content-addressable store (prune, add, status). `store prune` deletes orphaned packages used by no project on this machine."),
        ("patch", "Creates an editable copy of a dependency in a temp dir; `patch-commit` writes a persistent patch file consumed by future installs."),
    ].into_iter().collect()
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
        ("exec", "Runs an arbitrary command through the package manager (downloads the package if missing). Same trust boundary as `curl | bash` for untrusted packages."),
        ("install", "Installing packages"),
        ("add", "Adding packages"),
        ("remove", "Removing packages"),
        ("upgrade", "Upgrading packages"),
        ("upgrade-interactive", "Upgrading packages"),
        ("link", "Creates a global symlink and links the package into node_modules. Modifies the user-level yarn link registry; can shadow real installs of `<package>`."),
        ("unlink", "Removes the global symlink created by `yarn link`. Affects every project that consumed the linked package."),
        ("publish", "Publishes the package to its registry. Public publish is irreversible: the version number cannot be reused."),
        ("init", "Initializes a new package in the current directory by writing `package.json`."),
        ("create", "Runs a `create-<name>` package to scaffold a project, downloading it if missing. Same trust boundary as `curl | bash` for untrusted initializers."),
        ("dlx", "Runs an arbitrary command through the package manager (downloads the package if missing). Same trust boundary as `curl | bash` for untrusted packages."),
        ("cache", "Mutates the yarn cache (clean, list). `yarn cache clean` deletes all cached package tarballs."),
        ("global", "Operates on the user-global install location: add, remove, upgrade, bin, list. Modifies binaries on PATH for the current user."),
        ("set", "Sets a yarn config key. Affects the project's `.yarnrc.yml` (Berry) or the user-level `.yarnrc` (Classic)."),
    ].into_iter().collect()
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
        ("run", "Runs a command inside the project venv. Will create the venv and download missing dependencies from the lockfile on first run."),
        ("sync", "Reconciles the project venv with the lockfile. Installs missing deps and removes extras; can mutate the active `.venv`."),
        ("lock", "Resolves dependencies and writes `uv.lock`. Network access; pinned versions may change."),
        ("venv", "Creates a new virtual environment at `<path>` (default `.venv`). Overwrites an existing venv at the same path."),
        ("add", "Adding dependency"),
        ("remove", "Removing dependency"),
        ("tool", "Manages uv-installed standalone tools: install, uninstall, upgrade, run. Modifies the user-level uv tool directory and binaries on PATH."),
        ("python", "Manages uv-managed Python interpreters: install, uninstall, pin, find. Downloads interpreter builds and writes to the user-level uv data dir."),
        ("cache", "Mutates the uv cache (clean, prune). `uv cache clean` deletes all cached wheels and source distributions."),
        ("init", "Initializes a new uv project in the current directory by writing `pyproject.toml` and supporting files."),
        ("build", "Builds source and wheel distributions into `dist/`. Writes artifacts; does not publish."),
        ("publish", "Publishes the package to its registry. Public publish is irreversible: the version number cannot be reused."),
        ("pip install", "Installs packages into the currently active venv via uv's pip-compatible frontend. Writes to site-packages of `<venv>`."),
        ("pip uninstall", "Removes packages from the currently active venv via uv's pip-compatible frontend."),
    ].into_iter().collect()
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
        "nextest",
        "audit",
        "deny",
        "expand",
        "semver-checks",
        "llvm-cov",
        "outdated",
        "bloat",
        "machete",
        "depgraph",
    ]
    .into_iter()
    .collect()
});

pub static CARGO_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("watch", "Running commands on file changes"),
        ("mutants", "Mutation testing rewrites source files to introduce synthetic bugs and checks test coverage. Files are restored on completion; interrupting mid-run can leave the tree mutated."),
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
    ].into_iter().collect()
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
    if subcmd_single == "insta"
        && cmd
            .args
            .iter()
            .any(|a| ["review", "accept", "reject"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Snapshot testing"));
    }

    if CARGO_ALLOW.contains(subcmd.as_str()) || CARGO_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "clippy" && !cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }
    if subcmd_single == "insta"
        && !cmd
            .args
            .iter()
            .any(|a| ["review", "accept", "reject"].contains(&a.as_str()))
    {
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
        ("link", "Creates a global symlink and links the package into node_modules. Modifies bun's global link registry; can shadow real installs of `<package>`."),
        ("unlink", "Removes the global symlink created by `bun link`. Affects every project that consumed the linked package."),
        ("x", "Runs an arbitrary command through bun (downloads the package if missing). Same trust boundary as `curl | bash` for untrusted packages."),
        ("init", "Initializes a new bun project in the current directory by writing `package.json` and supporting files."),
        ("create", "Scaffolds a project from a `create-<name>` template, downloading it if missing. Same trust boundary as `curl | bash` for untrusted initializers."),
        ("publish", "Publishes the package to its registry. Public publish is irreversible: the version number cannot be reused."),
    ].into_iter().collect()
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
        ("clean", "Mutates the conda cache (packages, tarballs, indexes). Frees disk; next install re-downloads."),
        ("build", "Builds a conda package from a recipe. Writes artifacts under the conda-bld directory."),
        ("init", "Modifies shell rc files (`.bashrc`, `.zshrc`, etc.) to initialize conda on shell startup."),
        ("run", "Runs a command inside a named conda environment. Treat as executing that command with the env's interpreter on PATH."),
        ("env create", "Creates a new conda environment from a name or YAML spec. Downloads packages and writes under the conda envs dir."),
        ("env remove", "Deletes a named conda environment and everything installed in it. Not reversible without re-creation."),
    ].into_iter().collect()
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
        ("publish", "Publishes the package to its registry. Public publish is irreversible: the version number cannot be reused."),
        ("cache", "Mutates the poetry cache (clear, list). `poetry cache clear --all` deletes cached package tarballs and wheels."),
        ("export", "Writes the locked dependencies to a `requirements.txt`-style file. Output path may overwrite existing files."),
        ("self", "Manages the poetry installation itself: add, update, lock, sync of poetry plugins. Modifies the user-global poetry environment."),
        ("source", "Adds, removes, or shows package index sources in `pyproject.toml`. Changes where future installs resolve from."),
    ].into_iter().collect()
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
        "ls-remote",
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
        ("task", "Manages or runs mise tasks (run, ls, edit, add). `mise task run` executes shell from the task file; treat as running that script."),
        ("tasks", "Manages or runs mise tasks (run, ls, edit, add). `mise tasks run` executes shell from the task file; treat as running that script."),
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
        ("cache", "Mutates the mise cache (clear). Deletes cached tool downloads; next install will re-download."),
        ("link", "Symlinks an externally-installed tool version into mise's data dir so it can be selected like a managed version."),
    ].into_iter().collect()
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
        ("daemons start", "Starts a beads daemon process in the background. Daemons handle sync, hooks, and event delivery."),
        ("daemons stop", "Stops a running beads daemon process. Pauses background sync, hooks, and event delivery until restarted."),
        ("daemons restart", "Restarts a beads daemon process. Briefly pauses background sync, hooks, and event delivery."),
        ("daemons killall", "Kills every running beads daemon process on this machine. Stops background sync, hooks, and event delivery until restarted."),
        ("daemon start", "Starts a beads daemon process in the background. Daemons handle sync, hooks, and event delivery."),
        ("daemon stop", "Stops a running beads daemon process. Pauses background sync, hooks, and event delivery until restarted."),
        ("daemon restart", "Restarts a beads daemon process. Briefly pauses background sync, hooks, and event delivery."),
        ("daemon kill", "Force-kills a beads daemon process. May leave temporary state if the daemon was mid-write."),
        ("daemon run", "Runs a beads daemon in the foreground. Holds the terminal until interrupted."),
        ("hooks", "Managing git hooks"),
        ("migrate sync", "Migrating sync"),
        ("migrate issues", "Migrating issues"),
        ("migrate hash-ids", "Migrating hash IDs"),
        ("migrate tombstones", "Migrating tombstones"),
        ("admin", "Admin operation"),
        ("admin cleanup", "Cleaning up issues"),
        ("admin compact", "Compacting issues"),
        ("admin reset", "Resets the beads database. Drops all issues, history, and local state. Cannot be undone without a backup or remote sync."),
        ("compact", "Compacting old issues"),
        ("cleanup", "Cleaning up issues"),
        ("merge", "Merging issues"),
        ("repair", "Repairs the beads database from local logs and remote state. Can modify or roll back issue records to resolve inconsistencies."),
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
        ("reset", "Resets the beads database. Drops all issues, history, and local state. Cannot be undone without a backup or remote sync."),
    ].into_iter().collect()
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
        ("approve", "Adds a permanent permission rule to a Claude/Gemini/Codex settings file. Future matching tool calls auto-allow without prompting."),
        ("rules remove", "Removes a permission rule from a settings file. Future matching tool calls revert to the default gate decision."),
        ("pending clear", "Empties `~/.cache/tool-gates/pending.jsonl`. Drops every queued approval; cannot be undone."),
        ("hooks add", "Writes tool-gates hook entries into a Claude/Gemini/Codex settings file. Changes how every future tool call in that scope is gated."),
        ("review", "Opens the interactive approval TUI. Selecting Approve writes a permanent permission rule to a settings file."),
    ].into_iter().collect()
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
        return Some(GateResult::ask(
            "Re-scans the system for modern CLI tools (bat, rg, fd, etc.) and rewrites `~/.cache/tool-gates/available-tools.json`. Used to surface hints.",
        ));
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
    Some(GateResult::ask(
        "sd: sd in-place: rewrites the given files (regex find/replace). Without file args sd is a stdin->stdout pipe; with file args it modifies in place.",
    ))
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
        return Some(GateResult::ask(
            "sad --commit: applies the proposed search-and-replace to the matched files. Default sad without `--commit` is preview-only.",
        ));
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
        return Some(GateResult::ask(
            "ast-grep -U: applies the rewrite pattern across matched files. Default ast-grep is search-only; `-U`/`--update-all` writes the changes.",
        ));
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
        return Some(GateResult::ask(
            "yq -i: rewrites the YAML file in place per the given expression. Default yq prints to stdout; `-i`/`--inplace` writes the file.",
        ));
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
        return Some(GateResult::ask(
            "semgrep --autofix: applies rule-driven code rewrites to matched files. Default semgrep only reports findings.",
        ));
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
        return Some(GateResult::ask(
            "comby -in-place: applies the structural match-and-rewrite to the matched files. Default comby prints diffs to stdout.",
        ));
    }

    Some(GateResult::allow())
}

// === GRIT (from devtools.toml) ===

pub static GRIT_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("apply", "grit apply: applies a Grit migration pattern to matched files. Other grit subcommands are read-only/listing operations."),
    ].into_iter().collect()
});

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
    Some(GateResult::ask(
        "watchexec: watchexec: runs the given command whenever matching files change. The wrapped command's side effects fire on every change.",
    ))
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
        ("install", "lefthook install: writes hook scripts to `.git/hooks/` per `lefthook.yml`. Subsequent git operations invoke them."),
        ("uninstall", "lefthook uninstall: removes lefthook-managed hook scripts from `.git/hooks/`. Git stops invoking the configured hooks."),
        ("add", "lefthook add: creates hook script files under `.git/hooks/` for the named hook. Edits the git hooks directory."),
    ].into_iter().collect()
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

// === GOFUMPT (from devtools.toml) ===

/// Check gofumpt commands declaratively
pub fn check_gofumpt_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["gofumpt"].contains(&cmd.program.as_str()) {
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

// === PYTEST (from devtools.toml) ===

/// Check pytest commands declaratively
pub fn check_pytest_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pytest", "py.test"].contains(&cmd.program.as_str()) {
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

// === MYPY (from devtools.toml) ===

/// Check mypy commands declaratively
pub fn check_mypy_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mypy"].contains(&cmd.program.as_str()) {
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

// === PYRIGHT (from devtools.toml) ===

/// Check pyright commands declaratively
pub fn check_pyright_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pyright", "basedpyright"].contains(&cmd.program.as_str()) {
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

// === PYLINT (from devtools.toml) ===

/// Check pylint commands declaratively
pub fn check_pylint_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pylint"].contains(&cmd.program.as_str()) {
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

// === FLAKE8 (from devtools.toml) ===

/// Check flake8 commands declaratively
pub fn check_flake8_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["flake8"].contains(&cmd.program.as_str()) {
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

// === BANDIT (from devtools.toml) ===

/// Check bandit commands declaratively
pub fn check_bandit_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["bandit"].contains(&cmd.program.as_str()) {
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

// === COVERAGE (from devtools.toml) ===

pub static COVERAGE_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["report", "--version", "--help"].into_iter().collect());

pub static COVERAGE_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("run", "coverage run: executes the given Python script/module under coverage. Writes a `.coverage` data file in cwd."),
        ("html", "coverage html: writes an HTML report tree (default `htmlcov/`) from the current `.coverage` data file."),
        ("json", "coverage json: writes a `coverage.json` report file from the current `.coverage` data file."),
        ("xml", "coverage xml: writes a `coverage.xml` (Cobertura) report file from the current `.coverage` data file."),
        ("lcov", "coverage lcov: writes a `coverage.lcov` report file from the current `.coverage` data file."),
        ("erase", "coverage erase: deletes the `.coverage` data file in cwd. Pending reports cannot be regenerated without rerunning."),
        ("combine", "coverage combine: merges multiple `.coverage.*` data files into a single `.coverage` file. Inputs are consumed."),
    ].into_iter().collect()
});

/// Check coverage commands declaratively
pub fn check_coverage_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["coverage"].contains(&cmd.program.as_str()) {
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

    if COVERAGE_ALLOW.contains(subcmd.as_str()) || COVERAGE_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = COVERAGE_ASK
        .get(subcmd.as_str())
        .or_else(|| COVERAGE_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("coverage: {}", reason)));
    }

    Some(GateResult::ask(format!("coverage: {}", subcmd_single)))
}

// === TOX (from devtools.toml) ===

pub static TOX_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "--help"].into_iter().collect());

/// Check tox commands declaratively
pub fn check_tox_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["tox"].contains(&cmd.program.as_str()) {
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

    if TOX_ALLOW.contains(subcmd.as_str()) || TOX_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-l", "--list", "--listenvs"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any tox invocation asks
    Some(GateResult::ask(
        "tox: tox: runs the configured environments from `tox.ini` / `pyproject.toml`. Each env creates/uses a virtualenv and runs arbitrary commands per config.",
    ))
}

// === NOX (from devtools.toml) ===

pub static NOX_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "--help"].into_iter().collect());

/// Check nox commands declaratively
pub fn check_nox_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["nox"].contains(&cmd.program.as_str()) {
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

    if NOX_ALLOW.contains(subcmd.as_str()) || NOX_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-l", "--list"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any nox invocation asks
    Some(GateResult::ask(
        "nox: nox: runs the configured sessions from `noxfile.py`. Each session creates/uses a virtualenv and runs arbitrary Python code per the noxfile.",
    ))
}

// === AUTOFLAKE (from devtools.toml) ===

/// Check autoflake commands declaratively
pub fn check_autoflake_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["autoflake"].contains(&cmd.program.as_str()) {
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
            .any(|a| ["--in-place", "-i"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "autoflake --in-place: rewrites Python files to remove unused imports/variables. Default autoflake prints suggested diffs only.",
        ));
    }

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--check", "--check-diff"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("autoflake: {}", subcmd_single)))
}

// === TSX (from devtools.toml) ===

pub static TSX_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "--help"].into_iter().collect());

/// Check tsx commands declaratively
pub fn check_tsx_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["tsx"].contains(&cmd.program.as_str()) {
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

    if TSX_ALLOW.contains(subcmd.as_str()) || TSX_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any tsx invocation asks
    Some(GateResult::ask(
        "tsx: tsx: runs the given TypeScript file directly (Node + esbuild). The script's side effects (network, FS, child processes) execute.",
    ))
}

// === TS-NODE (from devtools.toml) ===

pub static TS_NODE_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "--help"].into_iter().collect());

/// Check ts-node commands declaratively
pub fn check_ts_node_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["ts-node"].contains(&cmd.program.as_str()) {
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

    if TS_NODE_ALLOW.contains(subcmd.as_str()) || TS_NODE_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any ts-node invocation asks
    Some(GateResult::ask(
        "ts-node: ts-node: runs the given TypeScript file under Node. The script's side effects (network, FS, child processes) execute.",
    ))
}

// === WEBPACK (from devtools.toml) ===

/// Check webpack commands declaratively
pub fn check_webpack_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["webpack", "webpack-cli"].contains(&cmd.program.as_str()) {
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

// === ROLLUP (from devtools.toml) ===

/// Check rollup commands declaratively
pub fn check_rollup_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["rollup"].contains(&cmd.program.as_str()) {
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

// === SWC (from devtools.toml) ===

/// Check swc commands declaratively
pub fn check_swc_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["swc"].contains(&cmd.program.as_str()) {
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

// === PARCEL (from devtools.toml) ===

pub static PARCEL_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["build", "--version", "--help"].into_iter().collect());

pub static PARCEL_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("serve", "parcel serve: starts the Parcel dev server on a local port. Binds to localhost until interrupted."),
        ("watch", "parcel watch: rebuilds the bundle on file changes. Long-running; writes output to the configured dist dir."),
    ].into_iter().collect()
});

/// Check parcel commands declaratively
pub fn check_parcel_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["parcel"].contains(&cmd.program.as_str()) {
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

    if PARCEL_ALLOW.contains(subcmd.as_str()) || PARCEL_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = PARCEL_ASK
        .get(subcmd.as_str())
        .or_else(|| PARCEL_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("parcel: {}", reason)));
    }

    Some(GateResult::ask(format!("parcel: {}", subcmd_single)))
}

// === PLAYWRIGHT (from devtools.toml) ===

pub static PLAYWRIGHT_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    ["test", "show-report", "show-trace", "--version", "--help"]
        .into_iter()
        .collect()
});

pub static PLAYWRIGHT_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "playwright install: downloads Chromium/Firefox/WebKit binaries to the Playwright cache (~300MB-1GB total)."),
        ("codegen", "playwright codegen: opens a browser and records user actions as test code. Writes the generated spec to stdout or `-o <file>`."),
    ].into_iter().collect()
});

/// Check playwright commands declaratively
pub fn check_playwright_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["playwright"].contains(&cmd.program.as_str()) {
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

    if PLAYWRIGHT_ALLOW.contains(subcmd.as_str()) || PLAYWRIGHT_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = PLAYWRIGHT_ASK
        .get(subcmd.as_str())
        .or_else(|| PLAYWRIGHT_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("playwright: {}", reason)));
    }

    Some(GateResult::ask(format!("playwright: {}", subcmd_single)))
}

// === CYPRESS (from devtools.toml) ===

pub static CYPRESS_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    ["run", "verify", "version", "info", "--version", "--help"]
        .into_iter()
        .collect()
});

pub static CYPRESS_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("open", "cypress open: launches the Cypress test runner GUI. Long-running until the window is closed."),
        ("install", "cypress install: downloads the Cypress binary to the local cache (~200MB)."),
    ].into_iter().collect()
});

/// Check cypress commands declaratively
pub fn check_cypress_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["cypress"].contains(&cmd.program.as_str()) {
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

    if CYPRESS_ALLOW.contains(subcmd.as_str()) || CYPRESS_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = CYPRESS_ASK
        .get(subcmd.as_str())
        .or_else(|| CYPRESS_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("cypress: {}", reason)));
    }

    Some(GateResult::ask(format!("cypress: {}", subcmd_single)))
}

// === WRANGLER (from devtools.toml) ===

pub static WRANGLER_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    ["whoami", "--version", "--help", "tail"]
        .into_iter()
        .collect()
});

pub static WRANGLER_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("dev", "wrangler dev: runs the Worker locally on a dev port. Long-running; binds to localhost until interrupted."),
        ("deploy", "Cloudflare wrangler deploy: publishes the Worker live to Cloudflare. Verify env vs preview vs production; the Worker starts handling traffic immediately."),
        ("publish", "Cloudflare wrangler publish: pushes the Worker live (older form of deploy). Verify env; the Worker starts handling traffic immediately."),
        ("login", "wrangler login: starts the OAuth flow and writes Cloudflare credentials to `~/.wrangler` (or `~/.config/.wrangler`). Anyone with read access to the file gets those credentials."),
        ("pages", "wrangler pages: Cloudflare Pages operation (deploy/dev/project). `pages deploy` publishes a site live to Cloudflare's edge."),
    ].into_iter().collect()
});

/// Check wrangler commands declaratively
pub fn check_wrangler_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["wrangler"].contains(&cmd.program.as_str()) {
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

    if WRANGLER_ALLOW.contains(subcmd.as_str()) || WRANGLER_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = WRANGLER_ASK
        .get(subcmd.as_str())
        .or_else(|| WRANGLER_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("wrangler: {}", reason)));
    }

    Some(GateResult::ask(format!("wrangler: {}", subcmd_single)))
}

// === TY (from devtools.toml) ===

/// Check ty commands declaratively
pub fn check_ty_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["ty"].contains(&cmd.program.as_str()) {
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
            .any(|a| ["--add-ignore"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "ty --add-ignore: inserts `ty: ignore` comments into source files at flagged diagnostics. Default ty only reports.",
        ));
    }

    Some(GateResult::allow())
}

// === MARKDOWNLINT (from devtools.toml) ===

/// Check markdownlint commands declaratively
pub fn check_markdownlint_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["markdownlint"].contains(&cmd.program.as_str()) {
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
            .any(|a| ["--fix", "-f"].contains(&a.as_str()))
    {
        return Some(GateResult::ask("Auto-fixing markdown"));
    }

    Some(GateResult::allow())
}

// === PYTHON3 (from runtimes.toml) ===

/// Check python3 commands declaratively
pub fn check_python3_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if ![
        "python3",
        "python",
        "python3.11",
        "python3.12",
        "python3.13",
        "python3.14",
    ]
    .contains(&cmd.program.as_str())
    {
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
    if true && cmd.args.iter().any(|a| ["-c"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Executes inline Python via `-c`. Treat the code as an inline script; can import any installed module.",
        ));
    }
    if true && cmd.args.iter().any(|a| ["-m"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Runs an installed Python module via `-m <module>`. Module code runs with the current interpreter; inherits the active venv if one is on PATH.",
        ));
    }

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--version", "-V", "-VV"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--help", "-h"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any python3 invocation asks
    Some(GateResult::ask(
        "python3: Runs a Python script file. The script runs with the current interpreter; inherits the active venv if one is on PATH.",
    ))
}

// === NODE (from runtimes.toml) ===

/// Check node commands declaratively
pub fn check_node_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["node"].contains(&cmd.program.as_str()) {
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
            .any(|a| ["-e", "--eval", "-p", "--print"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Executes inline JavaScript via `-e`. Treat the code as an inline script; full Node API access.",
        ));
    }

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--version", "-v"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
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
            .any(|a| ["-c", "--check"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any node invocation asks
    Some(GateResult::ask(
        "node: Runs a Node.js script file. Full Node API access including filesystem, network, and child processes.",
    ))
}

// === RUBY (from runtimes.toml) ===

/// Check ruby commands declaratively
pub fn check_ruby_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["ruby"].contains(&cmd.program.as_str()) {
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
    if true && cmd.args.iter().any(|a| ["-e"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Executes inline Ruby via `-e`. Treat the code as an inline script; full stdlib access.",
        ));
    }

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--version", "-v"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--help", "-h"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true && cmd.args.iter().any(|a| ["-c"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any ruby invocation asks
    Some(GateResult::ask(
        "ruby: Runs a Ruby script file. Full stdlib access including filesystem, network, and child processes.",
    ))
}

// === DENO (from runtimes.toml) ===

pub static DENO_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "--version",
        "-V",
        "--help",
        "-h",
        "check",
        "lint",
        "doc",
        "info",
        "types",
        "completions",
        "help",
        "test",
        "bench",
    ]
    .into_iter()
    .collect()
});

pub static DENO_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("run", "Runs a Deno script. Permissions are sandboxed by default; flags like `--allow-all` / `--allow-net` / `--allow-write` widen access."),
        ("serve", "Starts a Deno HTTP server. Binds a port (default 8000) and listens for incoming requests."),
        ("fmt", "Formats source files in place. Rewrites every matching file under the target paths."),
        ("compile", "Produces a standalone executable for the script. Writes a binary that embeds the Deno runtime and the script's modules."),
        ("install", "Installs a script as a global executable on PATH, or installs project dependencies. The global form writes to the Deno install root."),
        ("uninstall", "Removes a Deno-installed global executable from the Deno install root."),
        ("task", "Runs a named task from `deno.json`. Executes the task's shell command line; treat as running that command."),
        ("upgrade", "Replaces the Deno binary with a newer release. Modifies the installed `deno` executable on PATH."),
        ("add", "Adds a dependency to `deno.json` imports. Network fetch on next resolve."),
        ("remove", "Removes a dependency from `deno.json` imports."),
        ("publish", "Uploads the module to JSR. Public publish is irreversible: the version number cannot be reused."),
    ].into_iter().collect()
});

/// Check deno commands declaratively
pub fn check_deno_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["deno"].contains(&cmd.program.as_str()) {
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

    if DENO_ALLOW.contains(subcmd.as_str()) || DENO_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "fmt" && cmd.args.iter().any(|a| ["--check"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = DENO_ASK
        .get(subcmd.as_str())
        .or_else(|| DENO_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("deno: {}", reason)));
    }

    Some(GateResult::ask(format!("deno: {}", subcmd_single)))
}

// === PHP (from runtimes.toml) ===

/// Check php commands declaratively
pub fn check_php_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["php"].contains(&cmd.program.as_str()) {
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
    if true && cmd.args.iter().any(|a| ["-r"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Executes inline PHP via `-r`. Treat the code as an inline script.",
        ));
    }

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--version", "-v"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
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
            .any(|a| ["--info", "-i"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-l", "--syntax-check"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true && cmd.args.iter().any(|a| ["-m"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any php invocation asks
    Some(GateResult::ask(
        "php: Runs a PHP script file. Full PHP API access including filesystem, network, and shell execution.",
    ))
}

// === LUA (from runtimes.toml) ===

/// Check lua commands declaratively
pub fn check_lua_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["lua", "luajit", "lua5.1", "lua5.2", "lua5.3", "lua5.4"].contains(&cmd.program.as_str()) {
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
    if true && cmd.args.iter().any(|a| ["-e"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Executes inline Lua via `-e`. Treat the code as an inline script.",
        ));
    }

    // Check conditional allow rules
    if true && cmd.args.iter().any(|a| ["-v"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any lua invocation asks
    Some(GateResult::ask(
        "lua: Runs a Lua script file. Full Lua stdlib access including `io`, `os`, and loaded C modules.",
    ))
}

// === JAVA (from runtimes.toml) ===

/// Check java commands declaratively
pub fn check_java_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["java"].contains(&cmd.program.as_str()) {
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
            .any(|a| ["--version", "-version", "--help", "-help", "-h"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any java invocation asks
    Some(GateResult::ask(
        "java: Runs a Java class, JAR, or single source file. Full JVM access; classpath-loaded code runs unsandboxed.",
    ))
}

// === JAVAC (from runtimes.toml) ===

/// Check javac commands declaratively
pub fn check_javac_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["javac"].contains(&cmd.program.as_str()) {
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
            .any(|a| ["--version", "-version", "--help", "-help"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any javac invocation asks
    Some(GateResult::ask(
        "javac: Compiles Java source files into `.class` bytecode. Writes output to the configured destination directory.",
    ))
}

// === DOTNET (from runtimes.toml) ===

pub static DOTNET_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "--help", "-h", "help", "build", "test", "run", "clean", "restore", "list", "sln",
    ]
    .into_iter()
    .collect()
});

pub static DOTNET_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("publish", "Publishing application"),
        ("new", "Creating project"),
        ("add", "Adding reference/package"),
        ("remove", "Removing reference/package"),
        ("nuget", "NuGet operation"),
        ("tool", "Tool management"),
        ("pack", "Creating NuGet package"),
        ("format", "Formatting code"),
    ]
    .into_iter()
    .collect()
});

/// Check dotnet commands declaratively
pub fn check_dotnet_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["dotnet"].contains(&cmd.program.as_str()) {
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

    if DOTNET_ALLOW.contains(subcmd.as_str()) || DOTNET_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if true
        && cmd.args.iter().any(|a| {
            ["--version", "--info", "--list-sdks", "--list-runtimes"].contains(&a.as_str())
        })
    {
        return Some(GateResult::allow());
    }
    if subcmd_single == "format"
        && cmd
            .args
            .iter()
            .any(|a| ["--check", "--verify-no-changes"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    if let Some(reason) = DOTNET_ASK
        .get(subcmd.as_str())
        .or_else(|| DOTNET_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("dotnet: {}", reason)));
    }

    Some(GateResult::ask(format!("dotnet: {}", subcmd_single)))
}

// === SWIFT (from runtimes.toml) ===

pub static SWIFT_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["build", "test"].into_iter().collect());

pub static SWIFT_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("run", "Builds and runs the Swift executable target in the current package. Full Swift runtime access."),
        ("package", "Manages the Swift package: init, update, resolve, generate-xcodeproj, clean. Mutates `Package.resolved` and the build cache."),
    ].into_iter().collect()
});

/// Check swift commands declaratively
pub fn check_swift_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["swift"].contains(&cmd.program.as_str()) {
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

    if SWIFT_ALLOW.contains(subcmd.as_str()) || SWIFT_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--version", "--help", "-h"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    if let Some(reason) = SWIFT_ASK
        .get(subcmd.as_str())
        .or_else(|| SWIFT_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("swift: {}", reason)));
    }

    Some(GateResult::ask(format!("swift: {}", subcmd_single)))
}

// === ELIXIR (from runtimes.toml) ===

/// Check elixir commands declaratively
pub fn check_elixir_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["elixir"].contains(&cmd.program.as_str()) {
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
    if true && cmd.args.iter().any(|a| ["-e"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Executes inline Elixir via `-e`. Treat the code as an inline script.",
        ));
    }

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--version", "-v"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--help", "-h"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any elixir invocation asks
    Some(GateResult::ask(
        "elixir: Runs an Elixir script file (`.exs` / `.ex`). Full Elixir and Erlang stdlib access.",
    ))
}

// === IEX (from runtimes.toml) ===

/// Check iex commands declaratively
pub fn check_iex_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["iex"].contains(&cmd.program.as_str()) {
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
            .any(|a| ["--version", "-v"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any iex invocation asks
    Some(GateResult::ask(
        "iex: Starts the interactive Elixir REPL. Each input is evaluated with full Elixir and Erlang stdlib access.",
    ))
}

// === RM (from filesystem.toml) ===

pub static RM_BLOCK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        (
            "-rf /",
            "`rm -rf /` blocked: would recursively delete the entire root filesystem.",
        ),
        (
            "-rf /*",
            "`rm -rf /*` blocked: would recursively delete every top-level directory under root.",
        ),
        (
            "-rf ~",
            "`rm -rf ~` blocked: would recursively delete the user's home directory.",
        ),
        (
            "-fr /",
            "`rm -fr /` blocked: would recursively delete the entire root filesystem.",
        ),
        (
            "-fr ~",
            "`rm -fr ~` blocked: would recursively delete the user's home directory.",
        ),
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
    Some(GateResult::ask(
        "mv: Moves or renames files. Overwrites destination if it exists unless `-n` is set.",
    ))
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
    Some(GateResult::ask(
        "cp: Copies files or directories. Overwrites destination by default; `-n` to skip existing.",
    ))
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
    Some(GateResult::ask(
        "mkdir: Creates a directory. `-p` also creates missing parent directories.",
    ))
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
    Some(GateResult::ask(
        "rmdir: Removes empty directories. Fails if the directory contains files; use `rm -r` for non-empty trees.",
    ))
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
    Some(GateResult::ask(
        "touch: Creates an empty file or updates the mtime/atime of an existing one.",
    ))
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
    Some(GateResult::ask(
        "chmod: Changes file/dir mode bits. Use the minimum needed: 755 for dirs, 644 for files. Avoid 777 unless you know why.",
    ))
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
    Some(GateResult::ask(
        "chown: Changes file ownership. Verify the target user/group exists before running.",
    ))
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
    Some(GateResult::ask(
        "chgrp: Changes file group. Verify the target group exists before running.",
    ))
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
    Some(GateResult::ask(
        "ln: Creates a hard or symbolic link. `-s` for symlink, `-f` to overwrite an existing link target.",
    ))
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
    Some(GateResult::ask(
        "perl: perl can execute arbitrary code via `-e`, `-E`, `system()`, or backticks. Treat like running an inline script.",
    ))
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
    Some(GateResult::ask(
        "unzip: Extracts a zip archive. Verify trust; paths inside the archive can use `..` for directory traversal.",
    ))
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
    Some(GateResult::ask(
        "zip: Creates or modifies a zip archive. Writes the destination path; existing archives are updated in place.",
    ))
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
        return Some(GateResult::ask(
            "Downloads a file from the given URL. Writes to disk; `-O` chooses the output name, `-P` chooses the directory.",
        ));
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-r", "--recursive"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Recursively downloads pages and linked resources. Can fetch a large amount of data; control depth with `-l`.",
        ));
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-m", "--mirror"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Mirrors a site to local disk. Implies infinite recursion, timestamping, and link conversion.",
        ));
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--post-data", "--post-file"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Sends a POST request with the given body. Mutating HTTP method; server-side effects depend on the endpoint.",
        ));
    }

    if WGET_ALLOW.contains(subcmd.as_str()) || WGET_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if true && cmd.args.iter().any(|a| ["--spider"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any wget invocation asks
    Some(GateResult::ask(
        "wget: Downloads the given URL to the current directory by default. Writes to disk.",
    ))
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
    Some(GateResult::ask(
        "ssh: Opens an SSH connection. Commands executed on the remote bypass local tool-gates; treat the remote as a separate trust boundary.",
    ))
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
    Some(GateResult::ask(
        "scp: Copies files over SSH. Overwrites the destination by default; can transfer in either direction.",
    ))
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
    Some(GateResult::ask(
        "sftp: Opens an interactive SFTP session for transferring files over SSH.",
    ))
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
    Some(GateResult::ask(
        "rsync: Synchronizes files between source and destination. `--delete` removes files at the destination not present at source; preview with `-n` first.",
    ))
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
        return Some(GateResult::ask(
            "Opens a listening port. The `-e` flag (reverse shell) is blocked separately; verify firewall scope and that you intend to accept inbound connections.",
        ));
    }

    // Bare ask rule - any nc invocation asks
    Some(GateResult::ask(
        "nc: Opens a netcat connection to the given host/port. Sends/receives raw bytes; verify both endpoints.",
    ))
}

// === HTTP (from network.toml) ===

pub static HTTP_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "--help", "GET"].into_iter().collect());

pub static HTTP_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("POST", "Sends an HTTP POST request. Mutating method; server-side effects depend on the endpoint."),
        ("PUT", "Sends an HTTP PUT request. Typically replaces a resource at the target URL."),
        ("DELETE", "Sends an HTTP DELETE request. Typically removes the resource at the target URL."),
        ("PATCH", "Sends an HTTP PATCH request. Typically applies a partial update to the resource at the target URL."),
    ].into_iter().collect()
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

// === NMAP (from network.toml) ===

pub static NMAP_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "-V", "--help", "-h"].into_iter().collect());

/// Check nmap commands declaratively
pub fn check_nmap_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["nmap"].contains(&cmd.program.as_str()) {
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

    if NMAP_ALLOW.contains(subcmd.as_str()) || NMAP_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any nmap invocation asks
    Some(GateResult::ask(
        "nmap: Sends port-scan probes to remote hosts. Can be slow on large ranges and is logged by most network security tools.",
    ))
}

// === SOCAT (from network.toml) ===

pub static SOCAT_ALLOW: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "-V", "--help", "-h"].into_iter().collect());

/// Check socat commands declaratively
pub fn check_socat_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["socat"].contains(&cmd.program.as_str()) {
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

    if SOCAT_ALLOW.contains(subcmd.as_str()) || SOCAT_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any socat invocation asks
    Some(GateResult::ask(
        "socat: socat sets up bidirectional I/O between two endpoints (network, file, process). Confirm both endpoints; can be used to tunnel out of restricted environments.",
    ))
}

// === TELNET (from network.toml) ===

/// Check telnet commands declaratively
pub fn check_telnet_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["telnet"].contains(&cmd.program.as_str()) {
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

    // Bare ask rule - any telnet invocation asks
    Some(GateResult::ask(
        "telnet: Opens a cleartext telnet session to a host/port. No encryption; credentials sent in the clear.",
    ))
}

// === SHUTDOWN (from system.toml) ===

/// Check shutdown commands declaratively
pub fn check_shutdown_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["shutdown"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any shutdown invocation is blocked
    Some(GateResult::block(
        "shutdown: System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.",
    ))
}

// === REBOOT (from system.toml) ===

/// Check reboot commands declaratively
pub fn check_reboot_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["reboot"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any reboot invocation is blocked
    Some(GateResult::block(
        "reboot: System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.",
    ))
}

// === POWEROFF (from system.toml) ===

/// Check poweroff commands declaratively
pub fn check_poweroff_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["poweroff"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any poweroff invocation is blocked
    Some(GateResult::block(
        "poweroff: System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.",
    ))
}

// === HALT (from system.toml) ===

/// Check halt commands declaratively
pub fn check_halt_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["halt"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any halt invocation is blocked
    Some(GateResult::block(
        "halt: System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.",
    ))
}

// === INIT (from system.toml) ===

/// Check init commands declaratively
pub fn check_init_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["init"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any init invocation is blocked
    Some(GateResult::block(
        "init: System power command blocked: agent has no authority to shut down or reboot the machine. If genuinely needed, ask the user to run this themselves.",
    ))
}

// === MKFS (from system.toml) ===

/// Check mkfs commands declaratively
pub fn check_mkfs_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mkfs"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any mkfs invocation is blocked
    Some(GateResult::block(
        "mkfs: Disk partitioning blocked: agent has no authority to repartition disks. Mistakes here destroy data permanently. Ask the user to run partitioning themselves.",
    ))
}

// === FDISK (from system.toml) ===

/// Check fdisk commands declaratively
pub fn check_fdisk_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["fdisk"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any fdisk invocation is blocked
    Some(GateResult::block(
        "fdisk: Disk partitioning blocked: agent has no authority to repartition disks. Mistakes here destroy data permanently. Ask the user to run partitioning themselves.",
    ))
}

// === PARTED (from system.toml) ===

/// Check parted commands declaratively
pub fn check_parted_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["parted"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any parted invocation is blocked
    Some(GateResult::block(
        "parted: Disk partitioning blocked: agent has no authority to repartition disks. Mistakes here destroy data permanently. Ask the user to run partitioning themselves.",
    ))
}

// === GDISK (from system.toml) ===

/// Check gdisk commands declaratively
pub fn check_gdisk_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["gdisk"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any gdisk invocation is blocked
    Some(GateResult::block(
        "gdisk: Disk partitioning blocked: agent has no authority to repartition disks. Mistakes here destroy data permanently. Ask the user to run partitioning themselves.",
    ))
}

// === DD (from system.toml) ===

/// Check dd commands declaratively
pub fn check_dd_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["dd"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any dd invocation is blocked
    Some(GateResult::block(
        "dd: Low-level disk operation blocked: agent has no authority to run raw block-device writes. The wrong destination overwrites a disk without warning. Ask the user to run dd themselves.",
    ))
}

// === SHRED (from system.toml) ===

/// Check shred commands declaratively
pub fn check_shred_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["shred"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any shred invocation is blocked
    Some(GateResult::block(
        "shred: Secure delete blocked: agent has no authority to wipe files irreversibly. Ask the user to run shred themselves.",
    ))
}

// === WIPE (from system.toml) ===

/// Check wipe commands declaratively
pub fn check_wipe_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["wipe"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any wipe invocation is blocked
    Some(GateResult::block(
        "wipe: Secure wipe blocked: agent has no authority to wipe devices irreversibly. Ask the user to run wipe themselves.",
    ))
}

// === MKE2FS (from system.toml) ===

/// Check mke2fs commands declaratively
pub fn check_mke2fs_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mke2fs"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any mke2fs invocation is blocked
    Some(GateResult::block(
        "mke2fs: Filesystem creation blocked: agent has no authority to format filesystems. The wrong target erases data permanently. Ask the user to run mke2fs themselves.",
    ))
}

// === MKSWAP (from system.toml) ===

/// Check mkswap commands declaratively
pub fn check_mkswap_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["mkswap"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any mkswap invocation is blocked
    Some(GateResult::block(
        "mkswap: Swap creation blocked: agent has no authority to create swap areas on devices. The wrong target overwrites a device. Ask the user to run mkswap themselves.",
    ))
}

// === WIPEFS (from system.toml) ===

/// Check wipefs commands declaratively
pub fn check_wipefs_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["wipefs"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any wipefs invocation is blocked
    Some(GateResult::block(
        "wipefs: Filesystem wipe blocked: agent has no authority to wipe filesystem signatures. The wrong target destroys the partition table. Ask the user to run wipefs themselves.",
    ))
}

// === HDPARM (from system.toml) ===

/// Check hdparm commands declaratively
pub fn check_hdparm_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["hdparm"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any hdparm invocation is blocked
    Some(GateResult::block(
        "hdparm: Disk parameters blocked: agent has no authority to change disk-firmware parameters. Wrong values can brick drives. Ask the user to run hdparm themselves.",
    ))
}

// === INSMOD (from system.toml) ===

/// Check insmod commands declaratively
pub fn check_insmod_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["insmod"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any insmod invocation is blocked
    Some(GateResult::block(
        "insmod: Kernel module loading blocked: agent has no authority to load kernel modules. Module changes affect the entire running kernel. Ask the user to run this themselves.",
    ))
}

// === RMMOD (from system.toml) ===

/// Check rmmod commands declaratively
pub fn check_rmmod_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["rmmod"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any rmmod invocation is blocked
    Some(GateResult::block(
        "rmmod: Kernel module removal blocked: agent has no authority to unload kernel modules. Removal can destabilize the running kernel. Ask the user to run this themselves.",
    ))
}

// === MODPROBE (from system.toml) ===

/// Check modprobe commands declaratively
pub fn check_modprobe_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["modprobe"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any modprobe invocation is blocked
    Some(GateResult::block(
        "modprobe: Kernel module loading blocked: agent has no authority to load kernel modules. Module changes affect the entire running kernel. Ask the user to run this themselves.",
    ))
}

// === GRUB-INSTALL (from system.toml) ===

/// Check grub-install commands declaratively
pub fn check_grub_install_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["grub-install"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any grub-install invocation is blocked
    Some(GateResult::block(
        "grub-install: Bootloader modification blocked: agent has no authority to modify the bootloader. A bad bootloader leaves the system unbootable. Ask the user to run this themselves.",
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
        "update-grub: Bootloader modification blocked: agent has no authority to modify the bootloader. A bad bootloader leaves the system unbootable. Ask the user to run this themselves.",
    ))
}

// === USERADD (from system.toml) ===

/// Check useradd commands declaratively
pub fn check_useradd_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["useradd"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any useradd invocation is blocked
    Some(GateResult::block(
        "useradd: User management blocked: agent has no authority to create, delete, or modify user accounts. Account changes affect login and file ownership system-wide. Ask the user to run this themselves.",
    ))
}

// === USERDEL (from system.toml) ===

/// Check userdel commands declaratively
pub fn check_userdel_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["userdel"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any userdel invocation is blocked
    Some(GateResult::block(
        "userdel: User management blocked: agent has no authority to create, delete, or modify user accounts. Account changes affect login and file ownership system-wide. Ask the user to run this themselves.",
    ))
}

// === USERMOD (from system.toml) ===

/// Check usermod commands declaratively
pub fn check_usermod_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["usermod"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any usermod invocation is blocked
    Some(GateResult::block(
        "usermod: User management blocked: agent has no authority to create, delete, or modify user accounts. Account changes affect login and file ownership system-wide. Ask the user to run this themselves.",
    ))
}

// === PASSWD (from system.toml) ===

/// Check passwd commands declaratively
pub fn check_passwd_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["passwd"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any passwd invocation is blocked
    Some(GateResult::block(
        "passwd: Password change blocked: agent has no authority to change account passwords. Ask the user to run passwd themselves.",
    ))
}

// === CHSH (from system.toml) ===

/// Check chsh commands declaratively
pub fn check_chsh_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["chsh"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any chsh invocation is blocked
    Some(GateResult::block(
        "chsh: Shell change blocked: agent has no authority to change a user's login shell. Ask the user to run chsh themselves.",
    ))
}

// === IPTABLES (from system.toml) ===

/// Check iptables commands declaratively
pub fn check_iptables_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["iptables"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any iptables invocation is blocked
    Some(GateResult::block(
        "iptables: Firewall modification blocked: agent has no authority to modify firewall rules. Misconfigured rules can lock the user out of the system. Ask the user to run this themselves.",
    ))
}

// === UFW (from system.toml) ===

/// Check ufw commands declaratively
pub fn check_ufw_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["ufw"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any ufw invocation is blocked
    Some(GateResult::block(
        "ufw: Firewall modification blocked: agent has no authority to modify firewall rules. Misconfigured rules can lock the user out of the system. Ask the user to run this themselves.",
    ))
}

// === FIREWALL-CMD (from system.toml) ===

/// Check firewall-cmd commands declaratively
pub fn check_firewall_cmd_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["firewall-cmd"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any firewall-cmd invocation is blocked
    Some(GateResult::block(
        "firewall-cmd: Firewall modification blocked: agent has no authority to modify firewall rules. Misconfigured rules can lock the user out of the system. Ask the user to run this themselves.",
    ))
}

// === CHATTR (from system.toml) ===

/// Check chattr commands declaratively
pub fn check_chattr_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["chattr"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any chattr invocation is blocked
    Some(GateResult::block(
        "chattr: File attribute change blocked: agent has no authority to change extended file attributes. Misconfigured attributes can render files unmodifiable. Ask the user to run chattr themselves.",
    ))
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
    Some(GateResult::ask(
        "mount: Mounts a filesystem. Usually requires root in most setups; verify the source device and target mount point.",
    ))
}

// === UMOUNT (from system.toml) ===

/// Check umount commands declaratively
pub fn check_umount_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["umount"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any umount invocation is blocked
    Some(GateResult::block(
        "umount: Unmounting blocked: agent has no authority to unmount filesystems. Could disrupt running processes or system services depending on what's mounted. Ask the user to run umount themselves.",
    ))
}

// === SWAPOFF (from system.toml) ===

/// Check swapoff commands declaratively
pub fn check_swapoff_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["swapoff"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any swapoff invocation is blocked
    Some(GateResult::block(
        "swapoff: Swap management blocked: agent has no authority to enable or disable swap. Changes affect virtual memory behavior system-wide and can trigger OOM kills if swap is removed under load. Ask the user to run this themselves.",
    ))
}

// === SWAPON (from system.toml) ===

/// Check swapon commands declaratively
pub fn check_swapon_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["swapon"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any swapon invocation is blocked
    Some(GateResult::block(
        "swapon: Swap management blocked: agent has no authority to enable or disable swap. Changes affect virtual memory behavior system-wide and can trigger OOM kills if swap is removed under load. Ask the user to run this themselves.",
    ))
}

// === LVREMOVE (from system.toml) ===

/// Check lvremove commands declaratively
pub fn check_lvremove_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["lvremove"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any lvremove invocation is blocked
    Some(GateResult::block(
        "lvremove: LVM management blocked: agent has no authority to remove physical volumes, volume groups, or logical volumes. Removal is irreversible and can destroy mounted filesystems on top of the LVM stack. Ask the user to run this themselves.",
    ))
}

// === VGREMOVE (from system.toml) ===

/// Check vgremove commands declaratively
pub fn check_vgremove_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["vgremove"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any vgremove invocation is blocked
    Some(GateResult::block(
        "vgremove: LVM management blocked: agent has no authority to remove physical volumes, volume groups, or logical volumes. Removal is irreversible and can destroy mounted filesystems on top of the LVM stack. Ask the user to run this themselves.",
    ))
}

// === PVREMOVE (from system.toml) ===

/// Check pvremove commands declaratively
pub fn check_pvremove_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pvremove"].contains(&cmd.program.as_str()) {
        return None;
    }

    // Bare block rule - any pvremove invocation is blocked
    Some(GateResult::block(
        "pvremove: LVM management blocked: agent has no authority to remove physical volumes, volume groups, or logical volumes. Removal is irreversible and can destroy mounted filesystems on top of the LVM stack. Ask the user to run this themselves.",
    ))
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
    Some(GateResult::ask(
        "createdb: Creates a new PostgreSQL database. Connects to the server using the configured role.",
    ))
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
    Some(GateResult::ask(
        "dropdb: Drops a PostgreSQL database. Permanent; all schemas and data in the database are deleted.",
    ))
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
    Some(GateResult::ask(
        "pg_restore: Restores a PostgreSQL dump into a database. Can overwrite existing objects depending on flags.",
    ))
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
    Some(GateResult::ask(
        "migrate: Runs a database migration via golang-migrate. Applies schema changes; review the migration files first.",
    ))
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
    Some(GateResult::ask(
        "goose: Runs a database migration via goose. Applies schema changes; review the migration files first.",
    ))
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
    Some(GateResult::ask(
        "dbmate: Runs a database migration via dbmate. Applies schema changes; review the migration files first.",
    ))
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
    Some(GateResult::ask(
        "flyway: Runs a database migration via Flyway. Applies schema changes; review the migration files first.",
    ))
}

// === ALEMBIC (from system.toml) ===

pub static ALEMBIC_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    ["history", "current", "heads", "branches", "show"]
        .into_iter()
        .collect()
});

pub static ALEMBIC_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("upgrade", "Applies pending Alembic migrations to the database. Schema/data changes are not auto-reversible."),
        ("downgrade", "Reverts Alembic migrations. Can drop columns/tables; review the down() body before approving."),
        ("revision", "Generates a new Alembic migration file in the `versions/` directory."),
        ("stamp", "Sets the recorded Alembic version without running migrations. Mismatches with actual schema state can corrupt later migrations."),
    ].into_iter().collect()
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
    Some(GateResult::ask(
        "sqlite3: Opens a SQLite database file. Default mode allows writes; use `-readonly` to limit to queries.",
    ))
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
        return Some(GateResult::ask(
            "MongoDB session with `--eval` script. The eval body runs as JS in the database context and can mutate data.",
        ));
    }

    // Bare ask rule - any mongosh invocation asks
    Some(GateResult::ask(
        "mongosh: Opens a MongoDB session. Verify the connection target before running mutating queries.",
    ))
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
    Some(GateResult::ask(
        "kill: Sends a signal to the listed PIDs (default SIGTERM). Verify the PID first; `-9` (SIGKILL) cannot be caught and can corrupt state.",
    ))
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
    Some(GateResult::ask(
        "pkill: Signals processes matching a pattern. Run `pgrep <pattern>` first to verify which processes match; `-9` cannot be caught.",
    ))
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
    Some(GateResult::ask(
        "killall: Signals ALL processes with the given name. Verify which processes match (different from `kill <pid>`); `-9` cannot be caught.",
    ))
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
    Some(GateResult::ask(
        "xkill: Click-to-kill X11 utility. Sends a KILL signal to whatever window is clicked next.",
    ))
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
    Some(GateResult::ask(
        "cmake: Runs CMake to configure or build. Generates build files and may invoke the underlying compiler.",
    ))
}

// === NINJA (from system.toml) ===

pub static NINJA_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| ["-t"].into_iter().collect());

pub static NINJA_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [(
        "clean",
        "Removes Ninja build artifacts in the current build directory.",
    )]
    .into_iter()
    .collect()
});

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
        ("publish", "Publishes Gradle artifacts to a configured repository. Network operation; affects downstream consumers."),
        ("uploadArchives", "Uploads built archives to a configured Gradle repository."),
    ].into_iter().collect()
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
        ("install", "Installs the built Maven artifact into the local repository (`~/.m2/repository`)."),
        ("deploy", "Deploys Maven artifacts to a remote repository. Network operation; affects downstream consumers."),
    ].into_iter().collect()
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
    [
        ("clean", "Removes Bazel build outputs. `--expunge` also deletes the workspace's external dependencies."),
        ("run", "Builds and executes a Bazel target. The target runs as the current user with full filesystem access."),
    ].into_iter().collect()
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
        ("setup", "Configures a Meson build directory. Reads `meson.build` and writes build system files."),
        ("compile", "Compiles a Meson project. Invokes the underlying build backend (ninja by default)."),
        ("install", "Installs Meson build outputs to the configured prefix. May require root depending on prefix."),
    ].into_iter().collect()
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
    Some(GateResult::ask(
        "ansible: Runs an Ansible playbook against the inventory. Applies configuration changes to target hosts.",
    ))
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
        ("up", "Creates and boots the Vagrant VM defined in the local `Vagrantfile`."),
        ("halt", "Gracefully shuts down the running Vagrant VM."),
        ("destroy", "Deletes the Vagrant VM and its disk image. Cannot be undone; data inside the VM is lost."),
        ("provision", "Re-runs Vagrant provisioners against the running VM. Can apply configuration changes."),
        ("ssh", "Opens an SSH session into the Vagrant VM. Commands inside bypass local tool-gates."),
        ("reload", "Halts the Vagrant VM and brings it back up, re-applying Vagrantfile changes."),
    ].into_iter().collect()
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
    Some(GateResult::ask(
        "hyperfine: Runs the given command repeatedly to measure timing. Executes the wrapped command on each iteration.",
    ))
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
        ("start", "Starts a systemd unit. Side effects depend on the unit type (service, socket, timer, etc.)."),
        ("stop", "Stops a running systemd unit. Active connections/jobs handled by the unit may be cut off."),
        ("restart", "Stops and starts a systemd unit. Brief downtime; in-flight work in the unit may be lost."),
        ("reload", "Asks a systemd unit to reload its configuration without restarting. Unit must support SIGHUP-style reload."),
        ("enable", "Enables a systemd unit to start automatically at boot. Creates symlinks under `/etc/systemd/system/`."),
        ("disable", "Removes a systemd unit's autostart symlinks. Does not stop a currently running instance."),
        ("mask", "Symlinks a systemd unit to `/dev/null` so it cannot be started, even as a dependency."),
        ("unmask", "Removes a systemd mask, allowing the unit to be started again."),
        ("kill", "Sends a signal to processes of a systemd unit (default SIGTERM). `-s SIGKILL` cannot be caught."),
        ("reset-failed", "Clears the failed state of a systemd unit so it can be restarted."),
        ("daemon-reload", "Reloads systemd unit files. Required after editing a unit; doesn't restart running services on its own."),
        ("daemon-reexec", "Re-executes systemd itself. Drops PID 1 in-place and reloads its state; rarely needed."),
        ("set-default", "Changes the default systemd target the system boots into (e.g. `graphical.target` vs `multi-user.target`)."),
        ("isolate", "Switches systemd to the target unit and stops everything not required by it. Can take down unrelated services unexpectedly."),
        ("edit", "Opens a systemd unit override in `$EDITOR`. Interactive; may block in agent contexts."),
    ].into_iter().collect()
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
    Some(GateResult::ask(
        "crontab: Modifies cron jobs. Scheduled jobs persist across logout/reboot and run as the user; verify the schedule and command body.",
    ))
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
        ("download", "Downloads `.deb` package files to the current directory without installing."),
        ("install", "Installing packages"),
        ("remove", "Removes packages but keeps their config files. Use `purge` to also remove configs."),
        ("purge", "Removes packages and their config files. Stronger than `remove`."),
        ("update", "Updating package lists"),
        ("upgrade", "Upgrades installed packages to newer versions from the configured sources."),
        ("full-upgrade", "Upgrades packages and can remove others to resolve dependencies. Heavier than plain `upgrade`."),
        ("dist-upgrade", "Distribution upgrade can install/remove many packages, including kernel and base packages. Review proposed changes before approving."),
        ("autoremove", "Removes packages installed as dependencies that are no longer needed."),
        ("autoclean", "Removes obsolete `.deb` files from the apt download cache."),
        ("clean", "Removes all cached `.deb` files from the apt download cache."),
        ("build-dep", "Installs the build dependencies of the named source package."),
        ("source", "Downloads the source `.tar.*` and `.dsc` for a package into the current directory."),
        ("edit-sources", "Opens `/etc/apt/sources.list` in `$EDITOR`. Interactive; affects which repositories apt trusts."),
        ("satisfy", "Installs/removes packages as needed to satisfy a given dependency expression."),
    ].into_iter().collect()
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
        ("remove", "Removes packages from the system."),
        ("erase", "Removes packages from the system (alias for `remove`)."),
        ("update", "Updates installed packages to the latest version available in the enabled repos."),
        ("upgrade", "Upgrades installed packages (alias for `update`)."),
        ("downgrade", "Replaces installed packages with an older available version. May break dependencies."),
        ("reinstall", "Reinstalls already-installed packages, restoring overwritten files from the package payload."),
        ("autoremove", "Removes packages installed as dependencies that are no longer needed."),
        ("clean", "Cleans cached package data and metadata from the dnf cache."),
        ("makecache", "Downloads and caches repository metadata for enabled repos."),
        ("group", "Installs, removes, or queries a dnf package group."),
        ("module", "Installs, removes, enables, or queries dnf modules (streams of related packages)."),
        ("swap", "Atomically removes one package and installs another in its place."),
        ("distro-sync", "Synchronizes packages with the distribution version (can downgrade/upgrade across the repo set). Review changes before approving."),
    ].into_iter().collect()
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
        (
            "uninstall",
            "Removes installed Homebrew packages from the prefix.",
        ),
        (
            "remove",
            "Removes installed Homebrew packages (alias for `uninstall`).",
        ),
        (
            "upgrade",
            "Upgrades installed Homebrew formulae/casks to the latest available versions.",
        ),
        (
            "update",
            "Updates Homebrew's tap metadata. Does not upgrade installed packages.",
        ),
        (
            "reinstall",
            "Removes and re-installs a Homebrew formula or cask.",
        ),
        (
            "link",
            "Symlinks a formula's files into the Homebrew prefix.",
        ),
        (
            "unlink",
            "Removes a formula's symlinks from the Homebrew prefix without uninstalling.",
        ),
        (
            "pin",
            "Prevents a formula from being upgraded by `brew upgrade`.",
        ),
        ("unpin", "Removes a pin so a formula can be upgraded again."),
        (
            "tap",
            "Adds a third-party Homebrew tap to the list of trusted sources.",
        ),
        (
            "untap",
            "Removes a Homebrew tap and its formulae from the local list of sources.",
        ),
        (
            "cleanup",
            "Removes old versions of installed formulae and the download cache.",
        ),
        (
            "autoremove",
            "Removes Homebrew formulae installed as dependencies that are no longer needed.",
        ),
        (
            "services",
            "Manages Homebrew background services (start/stop/run/list).",
        ),
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
        ("in", "Installing packages (alias for `install`)."),
        ("remove", "Removes installed zypper packages."),
        ("rm", "Removes installed zypper packages (alias for `remove`)."),
        ("update", "Updates installed zypper packages to newer versions."),
        ("up", "Updates installed zypper packages (alias for `update`)."),
        ("dist-upgrade", "Distribution upgrade can install/remove many packages, including kernel and base packages. Review proposed changes before approving."),
        ("dup", "Distribution upgrade (alias for `dist-upgrade`)."),
        ("patch", "Installs official patches/errata for installed packages."),
        ("addrepo", "Adds a new zypper repository to the trusted list."),
        ("ar", "Adds a new zypper repository (alias for `addrepo`)."),
        ("removerepo", "Removes a configured zypper repository."),
        ("rr", "Removes a configured zypper repository (alias for `removerepo`)."),
        ("refresh", "Refreshes zypper repository metadata."),
        ("ref", "Refreshes zypper repository metadata (alias for `refresh`)."),
        ("clean", "Cleans cached zypper package data and metadata."),
    ].into_iter().collect()
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
        ("add", "Installs apk packages."),
        ("del", "Removes installed apk packages."),
        (
            "update",
            "Refreshes the apk package index from configured repositories.",
        ),
        (
            "upgrade",
            "Upgrades installed apk packages to newer versions.",
        ),
        (
            "fix",
            "Repairs an installed apk package whose files have been altered or removed.",
        ),
        (
            "cache",
            "Manages the apk package cache (clean, sync, download).",
        ),
        (
            "fetch",
            "Downloads apk packages to the current directory without installing.",
        ),
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
        ("build", "Builds a Nix derivation. May download from substituters or compile locally."),
        ("develop", "Enters a Nix development shell with the package's build dependencies in scope."),
        ("run", "Builds and runs the given Nix package. The package executes as the current user."),
        ("shell", "Opens an interactive shell with the given Nix packages available."),
        ("profile", "Installs, removes, or upgrades packages in a Nix user profile."),
        ("upgrade-nix", "Upgrades the Nix package manager itself to the latest version."),
        ("copy", "Copies Nix store paths between stores (local, remote, or s3). Network operation."),
        ("collect-garbage", "Deletes unreachable paths from the Nix store. Frees disk; cannot be undone without rebuilding."),
    ].into_iter().collect()
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
        (
            "-i",
            "Installs a Nix package into the current user profile.",
        ),
        (
            "--install",
            "Installs a Nix package into the current user profile.",
        ),
        (
            "-e",
            "Uninstalls a Nix package from the current user profile.",
        ),
        (
            "--uninstall",
            "Uninstalls a Nix package from the current user profile.",
        ),
        ("-u", "Upgrades packages in the current Nix user profile."),
        (
            "--upgrade",
            "Upgrades packages in the current Nix user profile.",
        ),
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
    Some(GateResult::ask(
        "nix-shell: Opens a shell with the given Nix expression's dependencies available. May download or build packages.",
    ))
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
        (
            "install",
            "Installs a Flatpak/Snap application from a remote.",
        ),
        (
            "uninstall",
            "Removes an installed Flatpak/Snap application.",
        ),
        (
            "remove",
            "Removes an installed Flatpak/Snap application (alias for `uninstall`).",
        ),
        ("update", "Updates installed Flatpak/Snap applications."),
        (
            "upgrade",
            "Upgrades installed Flatpak/Snap applications (alias for `update`).",
        ),
        ("run", "Launches an installed Flatpak/Snap application."),
        (
            "remote-add",
            "Adds a new Flatpak remote to the trusted list. Future installs can pull from it.",
        ),
        ("remote-delete", "Removes a configured Flatpak remote."),
        (
            "repair",
            "Repairs the local Flatpak installation. May re-download corrupted objects.",
        ),
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

// === DPKG (from system.toml) ===

/// Check dpkg commands declaratively
pub fn check_dpkg_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["dpkg"].contains(&cmd.program.as_str()) {
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
            .any(|a| ["-i", "--install"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Installs `.deb` package files directly via dpkg. Does not resolve dependencies; prefer `apt install` when possible.",
        ));
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-r", "--remove", "-P", "--purge"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Removes or purges installed packages via dpkg. `--purge` also removes config files.",
        ));
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--configure", "--unpack"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Configures or unpacks `.deb` packages. Used in low-level package management; can leave the system in a partially-configured state if interrupted.",
        ));
    }
    if true
        && cmd.args.iter().any(|a| {
            [
                "--set-selections",
                "--clear-selections",
                "--add-architecture",
                "--remove-architecture",
            ]
            .contains(&a.as_str())
        })
    {
        return Some(GateResult::ask(
            "Modifies dpkg package state (selections or supported architectures). Affects what apt/dpkg will install or upgrade.",
        ));
    }

    // Check conditional allow rules
    if true
        && cmd.args.iter().any(|a| {
            [
                "-l",
                "--list",
                "-L",
                "--listfiles",
                "-S",
                "--search",
                "-s",
                "--status",
                "-p",
                "--print-avail",
            ]
            .contains(&a.as_str())
        })
    {
        return Some(GateResult::allow());
    }
    if true
        && cmd.args.iter().any(|a| {
            [
                "--get-selections",
                "--print-architecture",
                "--print-foreign-architectures",
            ]
            .contains(&a.as_str())
        })
    {
        return Some(GateResult::allow());
    }
    if true
        && cmd.args.iter().any(|a| {
            [
                "--audit",
                "-C",
                "--yet-to-unpack",
                "--compare-versions",
                "--verify",
                "-V",
            ]
            .contains(&a.as_str())
        })
    {
        return Some(GateResult::allow());
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--version", "--help", "-?"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("dpkg: {}", subcmd_single)))
}

// === APT-MARK (from system.toml) ===

pub static APT_MARK_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "showmanual",
        "showauto",
        "showhold",
        "showinstall",
        "showremove",
        "showpurge",
        "--help",
    ]
    .into_iter()
    .collect()
});

pub static APT_MARK_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("manual", "Marks packages as manually installed so apt's autoremove will not remove them."),
        ("auto", "Marks packages as automatically installed so apt's autoremove can remove them when unused."),
        ("hold", "Pins a package at its current version. apt upgrade/install will refuse to change it."),
        ("unhold", "Releases a hold so the package can be upgraded again."),
        ("minimize-manual", "Marks as auto any manually-installed packages that are dependencies of other manually-installed packages."),
    ].into_iter().collect()
});

/// Check apt-mark commands declaratively
pub fn check_apt_mark_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["apt-mark"].contains(&cmd.program.as_str()) {
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

    if APT_MARK_ALLOW.contains(subcmd.as_str()) || APT_MARK_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = APT_MARK_ASK
        .get(subcmd.as_str())
        .or_else(|| APT_MARK_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("apt-mark: {}", reason)));
    }

    Some(GateResult::ask(format!("apt-mark: {}", subcmd_single)))
}

// === PACTL (from system.toml) ===

pub static PACTL_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list",
        "info",
        "stat",
        "get-default-sink",
        "get-default-source",
        "get-sink-volume",
        "get-source-volume",
        "get-sink-mute",
        "get-source-mute",
        "subscribe",
        "--version",
        "--help",
    ]
    .into_iter()
    .collect()
});

pub static PACTL_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("set-sink-volume", "Changes the volume of a PulseAudio output sink."),
        ("set-source-volume", "Changes the volume of a PulseAudio input source."),
        ("set-sink-mute", "Mutes or unmutes a PulseAudio output sink."),
        ("set-source-mute", "Mutes or unmutes a PulseAudio input source."),
        ("set-default-sink", "Changes which PulseAudio sink is the default for new streams."),
        ("set-default-source", "Changes which PulseAudio source is the default for new captures."),
        ("load-module", "Loads a PulseAudio module into the running daemon. Modules can route, filter, or expose audio."),
        ("unload-module", "Unloads a PulseAudio module from the running daemon."),
        ("exit", "Terminates the running PulseAudio daemon. Active audio streams will drop."),
    ].into_iter().collect()
});

/// Check pactl commands declaratively
pub fn check_pactl_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["pactl"].contains(&cmd.program.as_str()) {
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

    if PACTL_ALLOW.contains(subcmd.as_str()) || PACTL_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = PACTL_ASK
        .get(subcmd.as_str())
        .or_else(|| PACTL_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("pactl: {}", reason)));
    }

    Some(GateResult::ask(format!("pactl: {}", subcmd_single)))
}

// === OPENSSL (from system.toml) ===

pub static OPENSSL_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "version",
        "s_client",
        "dgst",
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "verify",
        "ciphers",
        "list",
        "asn1parse",
        "speed",
        "prime",
    ]
    .into_iter()
    .collect()
});

pub static OPENSSL_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("s_server", "Starts a debug TLS server bound to a local port. Accepts inbound connections until terminated."),
        ("genrsa", "Generates an RSA private key. Writes a private-key file; protect with passphrase and correct permissions."),
        ("genpkey", "Generates a private key (RSA/EC/Ed25519/etc.). Writes a private-key file; protect with passphrase and correct permissions."),
        ("req", "Creates a certificate signing request (CSR) or self-signed cert. Writes to disk."),
        ("ca", "Acts as a minimal certificate authority: signs CSRs, revokes certs, manages the CA database."),
        ("pkcs12", "Packs or unpacks a PKCS#12 bundle (cert + private key). Writes key material to disk."),
        ("enc", "Encrypts or decrypts a file with a symmetric cipher. Default cipher is weak; prefer `-aes-256-cbc` or modern alternatives."),
        ("smime", "S/MIME sign, verify, encrypt, or decrypt of an email message or file."),
        ("cms", "Cryptographic Message Syntax operation: sign, verify, encrypt, or decrypt a CMS structure."),
        ("rsautl", "RSA primitive operation: sign, verify, encrypt, or decrypt with an RSA key. Legacy; prefer `pkeyutl`."),
        ("pkeyutl", "Generic public-key operation: sign, verify, encrypt, decrypt, or derive shared secret."),
        ("ecparam", "Generates or inspects elliptic-curve parameters. With `-genkey`, also writes an EC private key."),
    ].into_iter().collect()
});

/// Check openssl commands declaratively
pub fn check_openssl_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["openssl"].contains(&cmd.program.as_str()) {
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
    if subcmd_single == "x509" && cmd.args.iter().any(|a| ["-req"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Signs a certificate request (CSR) to produce an X.509 certificate. Writes the resulting cert; affects trust if installed.",
        ));
    }
    if subcmd_single == "rand" && cmd.args.iter().any(|a| ["-out"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Writes the requested number of random bytes to the file given by `-out`.",
        ));
    }

    if OPENSSL_ALLOW.contains(subcmd.as_str()) || OPENSSL_ALLOW.contains(subcmd_single) {
        return Some(GateResult::allow());
    }

    // Check conditional allow rules
    if subcmd_single == "x509" && !cmd.args.iter().any(|a| ["-req"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }
    if subcmd_single == "rand" && !cmd.args.iter().any(|a| ["-out"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    if let Some(reason) = OPENSSL_ASK
        .get(subcmd.as_str())
        .or_else(|| OPENSSL_ASK.get(subcmd_single))
    {
        return Some(GateResult::ask(format!("openssl: {}", reason)));
    }

    Some(GateResult::ask(format!("openssl: {}", subcmd_single)))
}

// === GPG (from system.toml) ===

/// Check gpg commands declaratively
pub fn check_gpg_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["gpg", "gpg2"].contains(&cmd.program.as_str()) {
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
            .any(|a| ["--sign", "-s", "--clearsign", "--detach-sign", "-b"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Signs data with a GPG private key. `--clearsign` keeps the message readable; `--detach-sign` writes a separate `.sig` file.",
        ));
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--encrypt", "-e", "--symmetric", "-c"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Encrypts data with a GPG recipient key or a passphrase (`--symmetric`).",
        ));
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--decrypt", "-d"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Decrypts a GPG-encrypted file using the matching private key or passphrase.",
        ));
    }
    if true && cmd.args.iter().any(|a| ["--import"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Imports a GPG public or private key into the local keyring. The imported key becomes trusted for signature verification.",
        ));
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--export", "--export-secret-keys"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Exports a GPG key. `--export-secret-keys` exports private key material; protect the output file.",
        ));
    }
    if true
        && cmd.args.iter().any(|a| {
            [
                "--delete-key",
                "--delete-secret-key",
                "--delete-secret-and-public-key",
            ]
            .contains(&a.as_str())
        })
    {
        return Some(GateResult::ask(
            "Deletes a key from the local GPG keyring. `--delete-secret-key` removes private material; cannot be undone without a backup.",
        ));
    }
    if true
        && cmd.args.iter().any(|a| {
            [
                "--gen-key",
                "--generate-key",
                "--full-gen-key",
                "--full-generate-key",
                "--quick-gen-key",
            ]
            .contains(&a.as_str())
        })
    {
        return Some(GateResult::ask(
            "Generates a new GPG keypair. Writes private material to the keyring; choose a passphrase strong enough for the use case.",
        ));
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--edit-key"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Opens an interactive GPG key editor. May block in agent contexts; modifies the local keyring.",
        ));
    }

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--list-keys", "-k", "--list-secret-keys", "-K"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--fingerprint"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true && cmd.args.iter().any(|a| ["--verify"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--list-packets"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true && cmd.args.iter().any(|a| ["--version"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["--help", "-h"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }

    Some(GateResult::ask(format!("gpg: {}", subcmd_single)))
}

// === SSH-KEYGEN (from system.toml) ===

/// Check ssh-keygen commands declaratively
pub fn check_ssh_keygen_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["ssh-keygen"].contains(&cmd.program.as_str()) {
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
    if true && cmd.args.iter().any(|a| ["-R"].contains(&a.as_str())) {
        return Some(GateResult::ask(
            "Removes a host from the `known_hosts` file. Next connection will re-prompt for host key verification.",
        ));
    }

    // Check conditional allow rules
    if true
        && cmd
            .args
            .iter()
            .any(|a| ["-l", "-lf", "-lv"].contains(&a.as_str()))
    {
        return Some(GateResult::allow());
    }
    if true && cmd.args.iter().any(|a| ["-F"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }
    if true && cmd.args.iter().any(|a| ["-B"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any ssh-keygen invocation asks
    Some(GateResult::ask(
        "ssh-keygen: Generates or modifies an SSH key. Writes a private-key file; protect the output path and passphrase.",
    ))
}

// === AGE (from system.toml) ===

/// Check age commands declaratively
pub fn check_age_declarative(cmd: &CommandInfo) -> Option<GateResult> {
    if !["age", "age-keygen"].contains(&cmd.program.as_str()) {
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
    if true && cmd.args.iter().any(|a| ["--version"].contains(&a.as_str())) {
        return Some(GateResult::allow());
    }

    // Bare ask rule - any age invocation asks
    Some(GateResult::ask(
        "age: Encrypts or decrypts a file with age. Use `-i <key>` for identity files; output replaces or writes alongside the input.",
    ))
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
        return Some(GateResult::ask(
            "Updates the workflow state of story `<story>`. Moves it on the workflow board (e.g., To Do -> In Progress -> Done) and may trigger workflow automations.",
        ));
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
        return Some(GateResult::ask(
            "Archives story `<story>`. Hides it from default views but keeps history; reversible via `--archived=false` or the web UI.",
        ));
    }
    if subcmd_single == "workspace"
        && cmd
            .args
            .iter()
            .any(|a| ["-u", "--unset"].contains(&a.as_str()))
    {
        return Some(GateResult::ask(
            "Removes a saved workspace (named search query) from the local `short` config. Does not delete anything on shortcut.com.",
        ));
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
    if let Some(result) = check_gofumpt_declarative(cmd) {
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
    if let Some(result) = check_pytest_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_mypy_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_pyright_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_pylint_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_flake8_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_bandit_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_coverage_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_tox_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_nox_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_autoflake_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_tsx_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_ts_node_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_webpack_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_rollup_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_swc_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_parcel_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_playwright_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_cypress_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_wrangler_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_ty_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_markdownlint_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_python3_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_node_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_ruby_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_deno_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_php_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_lua_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_java_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_javac_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_dotnet_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_swift_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_elixir_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_iex_declarative(cmd) {
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
    if let Some(result) = check_nmap_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_socat_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_telnet_declarative(cmd) {
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
    if let Some(result) = check_dpkg_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_apt_mark_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_pactl_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_openssl_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_gpg_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_ssh_keygen_declarative(cmd) {
        return Some(result);
    }
    if let Some(result) = check_age_declarative(cmd) {
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

/// Generated gate for devtools - handles: sd, sad, ast-grep, sg, yq, jq, semgrep, comby, grit, watchexec, biome, prettier, eslint, ruff, black, isort, shellcheck, hadolint, golangci-lint, gci, air, actionlint, gitleaks, lefthook, vite, vitest, jest, mocha, tsc, tsup, esbuild, turbo, nx, knip, oxlint, gofmt, gofumpt, goimports, shfmt, rustfmt, stylua, clang-format, autopep8, rubocop, standardrb, patch, dos2unix, unix2dos, stylelint, mix, perltidy, dartfmt, dart, elm-format, scalafmt, ktlint, swiftformat, buf, pytest, py.test, mypy, pyright, basedpyright, pylint, flake8, bandit, coverage, tox, nox, autoflake, tsx, ts-node, webpack, webpack-cli, rollup, swc, parcel, playwright, cypress, wrangler, ty, markdownlint
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
        "gofumpt" => check_gofumpt_declarative(cmd).unwrap_or_else(GateResult::skip),
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
        "pytest" | "py.test" => check_pytest_declarative(cmd).unwrap_or_else(GateResult::skip),
        "mypy" => check_mypy_declarative(cmd).unwrap_or_else(GateResult::skip),
        "pyright" | "basedpyright" => {
            check_pyright_declarative(cmd).unwrap_or_else(GateResult::skip)
        }
        "pylint" => check_pylint_declarative(cmd).unwrap_or_else(GateResult::skip),
        "flake8" => check_flake8_declarative(cmd).unwrap_or_else(GateResult::skip),
        "bandit" => check_bandit_declarative(cmd).unwrap_or_else(GateResult::skip),
        "coverage" => check_coverage_declarative(cmd).unwrap_or_else(GateResult::skip),
        "tox" => check_tox_declarative(cmd).unwrap_or_else(GateResult::skip),
        "nox" => check_nox_declarative(cmd).unwrap_or_else(GateResult::skip),
        "autoflake" => check_autoflake_declarative(cmd).unwrap_or_else(GateResult::skip),
        "tsx" => check_tsx_declarative(cmd).unwrap_or_else(GateResult::skip),
        "ts-node" => check_ts_node_declarative(cmd).unwrap_or_else(GateResult::skip),
        "webpack" | "webpack-cli" => {
            check_webpack_declarative(cmd).unwrap_or_else(GateResult::skip)
        }
        "rollup" => check_rollup_declarative(cmd).unwrap_or_else(GateResult::skip),
        "swc" => check_swc_declarative(cmd).unwrap_or_else(GateResult::skip),
        "parcel" => check_parcel_declarative(cmd).unwrap_or_else(GateResult::skip),
        "playwright" => check_playwright_declarative(cmd).unwrap_or_else(GateResult::skip),
        "cypress" => check_cypress_declarative(cmd).unwrap_or_else(GateResult::skip),
        "wrangler" => check_wrangler_declarative(cmd).unwrap_or_else(GateResult::skip),
        "ty" => check_ty_declarative(cmd).unwrap_or_else(GateResult::skip),
        "markdownlint" => check_markdownlint_declarative(cmd).unwrap_or_else(GateResult::skip),
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
    "gofumpt",
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
    "pytest",
    "py.test",
    "mypy",
    "pyright",
    "basedpyright",
    "pylint",
    "flake8",
    "bandit",
    "coverage",
    "tox",
    "nox",
    "autoflake",
    "tsx",
    "ts-node",
    "webpack",
    "webpack-cli",
    "rollup",
    "swc",
    "parcel",
    "playwright",
    "cypress",
    "wrangler",
    "ty",
    "markdownlint",
];

/// Generated gate for runtimes - handles: python3, python, python3.11, python3.12, python3.13, python3.14, node, ruby, deno, php, lua, luajit, lua5.1, lua5.2, lua5.3, lua5.4, java, javac, dotnet, swift, elixir, iex
/// Custom handlers needed for: []
pub fn check_runtimes_gate(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "python3" | "python" | "python3.11" | "python3.12" | "python3.13" | "python3.14" => {
            check_python3_declarative(cmd).unwrap_or_else(GateResult::skip)
        }
        "node" => check_node_declarative(cmd).unwrap_or_else(GateResult::skip),
        "ruby" => check_ruby_declarative(cmd).unwrap_or_else(GateResult::skip),
        "deno" => check_deno_declarative(cmd).unwrap_or_else(GateResult::skip),
        "php" => check_php_declarative(cmd).unwrap_or_else(GateResult::skip),
        "lua" | "luajit" | "lua5.1" | "lua5.2" | "lua5.3" | "lua5.4" => {
            check_lua_declarative(cmd).unwrap_or_else(GateResult::skip)
        }
        "java" => check_java_declarative(cmd).unwrap_or_else(GateResult::skip),
        "javac" => check_javac_declarative(cmd).unwrap_or_else(GateResult::skip),
        "dotnet" => check_dotnet_declarative(cmd).unwrap_or_else(GateResult::skip),
        "swift" => check_swift_declarative(cmd).unwrap_or_else(GateResult::skip),
        "elixir" => check_elixir_declarative(cmd).unwrap_or_else(GateResult::skip),
        "iex" => check_iex_declarative(cmd).unwrap_or_else(GateResult::skip),
        _ => GateResult::skip(),
    }
}

/// Programs handled by the runtimes gate
pub static RUNTIMES_PROGRAMS: &[&str] = &[
    "python3",
    "python",
    "python3.11",
    "python3.12",
    "python3.13",
    "python3.14",
    "node",
    "ruby",
    "deno",
    "php",
    "lua",
    "luajit",
    "lua5.1",
    "lua5.2",
    "lua5.3",
    "lua5.4",
    "java",
    "javac",
    "dotnet",
    "swift",
    "elixir",
    "iex",
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

/// Generated gate for network - handles: curl, wget, ssh, scp, sftp, rsync, nc, ncat, netcat, http, https, xh, nmap, socat, telnet
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
        "nmap" => check_nmap_declarative(cmd).unwrap_or_else(GateResult::skip),
        "socat" => check_socat_declarative(cmd).unwrap_or_else(GateResult::skip),
        "telnet" => check_telnet_declarative(cmd).unwrap_or_else(GateResult::skip),
        _ => GateResult::skip(),
    }
}

/// Programs handled by the network gate
pub static NETWORK_PROGRAMS: &[&str] = &[
    "curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "http", "https", "xh",
    "nmap", "socat", "telnet",
];

/// Generated gate for system - handles: shutdown, reboot, poweroff, halt, init, mkfs, fdisk, parted, gdisk, dd, shred, wipe, mke2fs, mkswap, wipefs, hdparm, insmod, rmmod, modprobe, grub-install, update-grub, useradd, userdel, usermod, passwd, chsh, iptables, ufw, firewall-cmd, chattr, mount, umount, swapoff, swapon, lvremove, vgremove, pvremove, psql, createdb, dropdb, pg_dump, pg_restore, migrate, goose, dbmate, flyway, alembic, mysql, sqlite3, mongosh, mongo, redis-cli, kill, pkill, killall, xkill, make, cmake, ninja, just, task, gradle, gradlew, ./gradlew, mvn, maven, ./mvnw, mvnw, bazel, bazelisk, meson, ansible, ansible-playbook, ansible-galaxy, ansible-vault, vagrant, hyperfine, sudo, doas, systemctl, service, crontab, apt, apt-get, apt-cache, dnf, yum, pacman, yay, paru, brew, zypper, apk, nix, nix-env, nix-shell, flatpak, snap, dpkg, apt-mark, pactl, openssl, gpg, gpg2, ssh-keygen, age, age-keygen
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
        "dpkg" => check_dpkg_declarative(cmd).unwrap_or_else(GateResult::skip),
        "apt-mark" => check_apt_mark_declarative(cmd).unwrap_or_else(GateResult::skip),
        "pactl" => check_pactl_declarative(cmd).unwrap_or_else(GateResult::skip),
        "openssl" => check_openssl_declarative(cmd).unwrap_or_else(GateResult::skip),
        "gpg" | "gpg2" => check_gpg_declarative(cmd).unwrap_or_else(GateResult::skip),
        "ssh-keygen" => check_ssh_keygen_declarative(cmd).unwrap_or_else(GateResult::skip),
        "age" | "age-keygen" => check_age_declarative(cmd).unwrap_or_else(GateResult::skip),
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
    "dpkg",
    "apt-mark",
    "pactl",
    "openssl",
    "gpg",
    "gpg2",
    "ssh-keygen",
    "age",
    "age-keygen",
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
        "autoflake",
        "autopep8",
        "biome",
        "black",
        "buf",
        "cargo",
        "clang-format",
        "comby",
        "dart",
        "dartfmt",
        "deno",
        "dos2unix",
        "dotnet",
        "elm-format",
        "eslint",
        "gci",
        "go",
        "gofmt",
        "gofumpt",
        "goimports",
        "golangci-lint",
        "grit",
        "isort",
        "ktlint",
        "markdownlint",
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
        "ty",
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

    // Reject scoped npm packages: @scope/tool should not match bare "tool".
    // rsplit('/') strips the scope, which would let @evil/prettier match "prettier".
    if cmd.program.starts_with('@') && base_program != cmd.program {
        return false;
    }

    // Quick check: is this a known file-editing program?
    if !FILE_EDITING_PROGRAMS.contains(base_program) {
        return false;
    }

    match base_program {
        "ast-grep" => cmd
            .args
            .iter()
            .any(|a| ["-U", "--update-all"].contains(&a.as_str())),
        "autoflake" => cmd
            .args
            .iter()
            .any(|a| ["--in-place", "-i"].contains(&a.as_str())),
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
        "deno" => cmd.args.first().is_some_and(|a| a == "fmt"),
        "dos2unix" => {
            // Bare rule: always file-editing
            true
        }
        "dotnet" => cmd.args.first().is_some_and(|a| a == "format"),
        "elm-format" => {
            // Bare rule: always file-editing
            true
        }
        "eslint" => cmd.args.iter().any(|a| ["--fix"].contains(&a.as_str())),
        "gci" => cmd.args.iter().any(|a| ["write"].contains(&a.as_str())),
        "go" => cmd.args.first().is_some_and(|a| a == "fmt"),
        "gofmt" => cmd.args.iter().any(|a| ["-w"].contains(&a.as_str())),
        "gofumpt" => cmd.args.iter().any(|a| ["-w"].contains(&a.as_str())),
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
        "markdownlint" => cmd
            .args
            .iter()
            .any(|a| ["--fix", "-f"].contains(&a.as_str())),
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
        "ty" => cmd
            .args
            .iter()
            .any(|a| ["--add-ignore"].contains(&a.as_str())),
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

//! Filesystem command permission gate.
//!
//! Uses declarative rules with custom logic for:
//! - Path normalization and traversal detection (security critical)
//! - tar flag parsing (combined flags like -xzf)

use crate::gates::helpers::{
    BLOCKED_SECURITY_DIRS_UNDER_HOME, expand_path_vars, is_suspicious_path, normalize_path,
};
use crate::generated::rules::{
    check_chmod_declarative, check_cp_declarative, check_ln_declarative, check_mkdir_declarative,
    check_mv_declarative, check_perl_declarative, check_rm_declarative, check_rmdir_declarative,
    check_touch_declarative,
};
use crate::models::{CommandInfo, Decision, GateResult};

/// Check filesystem commands.
pub fn check_filesystem(cmd: &CommandInfo) -> GateResult {
    // Strip path prefix to handle /usr/bin/rm etc.
    let program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);
    let args = &cmd.args;

    match program {
        "rm" => check_rm(cmd),
        "mv" => check_mv_declarative(cmd).unwrap_or_else(|| GateResult::ask("mv: Moving files")),
        "cp" => check_cp(cmd),
        "mkdir" => check_mkdir(cmd),
        "rmdir" => check_rmdir_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("rmdir: Removing directory (if empty)")),
        "touch" => check_touch(cmd),
        "chmod" | "chown" | "chgrp" => check_chmod_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask(format!("{program}: Changing permissions"))),
        "ln" => check_ln_declarative(cmd).unwrap_or_else(|| GateResult::ask("ln: Creating link")),
        "sed" if args.iter().any(|a| a == "-i") => GateResult::ask("sed -i: In-place edit"),
        // perl can execute arbitrary code even without -i (via -e, system(), etc.)
        "perl" => check_perl_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("perl: can execute arbitrary code")),
        "tar" => check_tar(cmd),
        "unzip" => check_unzip(cmd),
        "zip" => check_zip(cmd),
        _ => GateResult::skip(),
    }
}

/// Non-flag path arguments, with one layer of surrounding quotes stripped
/// (the bash parser can hand back quoted tokens for paths containing `$VAR`).
fn path_args(cmd: &CommandInfo) -> Vec<&str> {
    cmd.args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(|a| a.trim_matches(|c| c == '"' || c == '\'').trim())
        .filter(|a| !a.is_empty())
        .collect()
}

/// True when every path argument resolves under the session scratch base.
fn all_path_args_under_scratch(cmd: &CommandInfo) -> bool {
    let paths = path_args(cmd);
    !paths.is_empty() && paths.iter().all(|p| crate::router::is_under_scratch(p))
}

/// Upgrade an `Ask` result to `Allow` when the scratch condition holds; leaves
/// `Block`/`Skip`/`Allow` results untouched so a future block rule still wins.
fn upgrade_to_scratch_allow(base: GateResult, under_scratch: bool, reason: &str) -> GateResult {
    if base.decision == Decision::Ask && under_scratch {
        return GateResult::allow_with_reason(reason);
    }
    base
}

/// `mkdir` into the session scratch dir is friction-free (agents create their
/// per-session scratch subtree there instead of `/tmp`); anything else asks.
fn check_mkdir(cmd: &CommandInfo) -> GateResult {
    let base = check_mkdir_declarative(cmd)
        .unwrap_or_else(|| GateResult::ask("mkdir: Creating directory"));
    upgrade_to_scratch_allow(
        base,
        all_path_args_under_scratch(cmd),
        "mkdir into scratch directory",
    )
}

/// `touch` into the session scratch dir is friction-free; anything else asks.
fn check_touch(cmd: &CommandInfo) -> GateResult {
    let base = check_touch_declarative(cmd)
        .unwrap_or_else(|| GateResult::ask("touch: Creating/updating file"));
    upgrade_to_scratch_allow(
        base,
        all_path_args_under_scratch(cmd),
        "touch into scratch directory",
    )
}

/// `cp` is allowed only when the destination (last path arg) is under scratch.
/// Reading a source elsewhere is harmless; `cp scratch/x /etc/y` must still ask.
fn check_cp(cmd: &CommandInfo) -> GateResult {
    let base = check_cp_declarative(cmd).unwrap_or_else(|| GateResult::ask("cp: Copying files"));
    let dest_under_scratch = path_args(cmd)
        .last()
        .map(|p| crate::router::is_under_scratch(p))
        .unwrap_or(false);
    upgrade_to_scratch_allow(base, dest_under_scratch, "cp into scratch directory")
}

/// Check rm command - requires custom path normalization.
fn check_rm(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Try declarative first for blocks
    if let Some(result) = check_rm_declarative(cmd) {
        if matches!(result.decision, Decision::Block) {
            return result;
        }
    }

    // Literal catastrophic forms - blocked even when HOME is unset.
    let literal_catastrophic = ["/", "/*", "~", "~/"];

    // Runtime catastrophic set. Can't be const because it depends on the
    // resolved home directory and the security-critical dotdirs under it.
    //
    // Two parallel lists:
    // - `resolved_catastrophic`: paths to match exactly (or with `/*` glob)
    // - `resolved_catastrophic_prefix`: directory roots; any path AT or
    //   UNDER one is blocked. Used so `rm -rf $HOME/.aws/credentials`
    //   also blocks, not just `rm -rf $HOME/.aws`.
    let mut resolved_catastrophic: Vec<String> = Vec::new();
    let mut resolved_catastrophic_prefix: Vec<String> = Vec::new();
    if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy().into_owned();
        resolved_catastrophic.push(home_str.clone());
        resolved_catastrophic.push(format!("{home_str}/*"));
        for dotdir in BLOCKED_SECURITY_DIRS_UNDER_HOME {
            let dir_path = format!("{home_str}{dotdir}");
            resolved_catastrophic.push(dir_path.clone());
            resolved_catastrophic.push(format!("{dir_path}/*"));
            resolved_catastrophic_prefix.push(dir_path);
        }
    }

    for arg in args {
        // Skip flags. The recursive-flag check below handles -r/-rf.
        if arg.starts_with('-') {
            continue;
        }

        // 1. Literal symbolic match (works even without HOME).
        if literal_catastrophic.contains(&arg.as_str()) {
            return GateResult::block(format!(
                "rm '{arg}' blocked: recursive deletion of this path would destroy critical system or home directory contents. No legitimate agent use case. To clear scratch files, target a specific subpath and verify with `eza` first."
            ));
        }

        // 2. Fail closed on unresolvable home/user vars in rm targets.
        let expanded = match expand_path_vars(arg) {
            Some(e) => e,
            None => {
                return GateResult::block(format!(
                    "rm '{arg}' blocked: the path contains an unset variable like `$HOME` that didn't expand, so the literal text would be passed to rm. tool-gates fails closed when it can't tell what path will be deleted. Verify the variable is set, or pass an absolute path."
                ));
            }
        };

        // 3. Normalize both the raw arg and the expanded form.
        let arg_normalized = normalize_path(arg);
        let expanded_normalized = normalize_path(&expanded);

        // Check the literal catastrophic set against the normalized arg
        // (catches // , /./ , /// etc.).
        if literal_catastrophic.contains(&arg_normalized.as_str()) {
            return GateResult::block(format!(
                "rm '{arg}' blocked: recursive deletion of this path would destroy critical system or home directory contents. No legitimate agent use case. To clear scratch files, target a specific subpath and verify with `eza` first."
            ));
        }

        // Check the runtime catastrophic set against both the expanded
        // form and its normalized variant.
        for cat in &resolved_catastrophic {
            if expanded == *cat
                || expanded_normalized == *cat
                || expanded_normalized.trim_end_matches('/') == cat.trim_end_matches('/')
            {
                return GateResult::block(format!(
                    "rm '{arg}' blocked: recursive deletion of this path would destroy critical system or home directory contents. No legitimate agent use case. To clear scratch files, target a specific subpath and verify with `eza` first."
                ));
            }
        }

        // Anything AT OR UNDER a security-critical directory is catastrophic
        // for rm. Catches files inside the dotdir like
        // `$HOME/.aws/credentials` or `$HOME/.ssh/id_rsa`.
        for prefix in &resolved_catastrophic_prefix {
            let p_with_slash = format!("{prefix}/");
            if expanded_normalized == *prefix || expanded_normalized.starts_with(&p_with_slash) {
                return GateResult::block(format!(
                    "rm '{arg}' blocked: this targets a security-critical directory (`.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.config/gh`, `.password-store`, or `.vault-token`). Deleting these breaks credentials or trust state. If genuinely needed, ask the user to run rm themselves."
                ));
            }
        }

        // /tmp/../ style traversal.
        if is_suspicious_path(arg) || is_suspicious_path(&expanded) {
            return GateResult::block(format!(
                "rm '{arg}' blocked: the path uses `..` traversal that resolves to `/` or near-root. Likely a malformed path or injection attempt. Use an absolute path that doesn't traverse upward."
            ));
        }
    }

    // High-risk paths - ask with warning
    let risky_paths = ["../", "..", "*"];
    for arg in args {
        if risky_paths.contains(&arg.as_str()) {
            return GateResult::ask(format!("rm: Target '{arg}' (verify intended)"));
        }
    }

    // Recursive delete - ask
    if args
        .iter()
        .any(|a| a == "-r" || a == "-rf" || a == "-fr" || a == "--recursive")
    {
        return GateResult::ask("rm: Recursive delete");
    }

    GateResult::ask("rm: Deleting file(s)")
}

/// Check tar command - custom flag parsing for combined flags.
fn check_tar(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // List contents is safe (check combined flags like -tvf)
    if args.iter().any(|a| a == "-t" || a == "--list") {
        return GateResult::allow();
    }
    for arg in args {
        if arg.starts_with('-') && !arg.starts_with("--") && arg.contains('t') {
            return GateResult::allow();
        }
    }

    // Extraction or creation (handle combined flags like -xf, -cf, -xzf)
    for arg in args {
        if arg.starts_with('-')
            && !arg.starts_with("--")
            && (arg.contains('x') || arg.contains('c'))
        {
            return GateResult::ask("tar: Archive operation");
        }
    }

    if args.iter().any(|a| a == "--extract" || a == "--create") {
        return GateResult::ask("tar: Archive operation");
    }

    GateResult::allow()
}

/// Check unzip command.
fn check_unzip(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // List contents is safe
    if args.iter().any(|a| a == "-l") {
        return GateResult::allow();
    }

    GateResult::ask("unzip: Extracting archive")
}

/// Check zip command.
/// Note: -l flag converts line endings (CR-LF to Unix), it does NOT list contents.
/// Use zipinfo to list zip contents (which is in basics safe_commands).
fn check_zip(_cmd: &CommandInfo) -> GateResult {
    GateResult::ask("zip: Creating/modifying archive")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    // === scratch dir auto-allow (mkdir / touch / cp) ===

    #[serial_test::serial]
    #[test]
    fn test_filesystem_scratch_auto_allow() {
        let saved = std::env::var("TOOL_GATES_SCRATCH").ok();
        // SAFETY: serialized via #[serial], so no concurrent env access.
        unsafe {
            std::env::set_var("TOOL_GATES_SCRATCH", "/tmp/cc-scratch-test");
        }

        // mkdir / touch into scratch -> allow (absolute, token, and braced forms).
        for c in [
            cmd("mkdir", &["-p", "/tmp/cc-scratch-test/p/s"]),
            cmd("mkdir", &["-p", "$TOOL_GATES_SCRATCH/p/s"]),
            cmd("mkdir", &["${TOOL_GATES_SCRATCH}/p"]),
            cmd("touch", &["/tmp/cc-scratch-test/p/note.txt"]),
        ] {
            assert_eq!(
                check_filesystem(&c).decision,
                Decision::Allow,
                "scratch target should auto-allow: {:?}",
                c.args
            );
        }

        // Same programs outside scratch -> still ask.
        for c in [
            cmd("mkdir", &["-p", "/tmp/other/p"]),
            cmd("touch", &["/etc/note.txt"]),
        ] {
            assert_eq!(
                check_filesystem(&c).decision,
                Decision::Ask,
                "non-scratch target should ask: {:?}",
                c.args
            );
        }

        // A `..` escape out of scratch must not be treated as scratch.
        assert_eq!(
            check_filesystem(&cmd("mkdir", &["-p", "/tmp/cc-scratch-test/../escape"])).decision,
            Decision::Ask,
            "path escaping scratch via .. should ask"
        );

        // cp: destination under scratch allows; source under scratch with an
        // outside destination must still ask.
        assert_eq!(
            check_filesystem(&cmd("cp", &["/etc/hosts", "/tmp/cc-scratch-test/hosts"])).decision,
            Decision::Allow,
            "cp into scratch should allow"
        );
        assert_eq!(
            check_filesystem(&cmd("cp", &["/tmp/cc-scratch-test/hosts", "/etc/evil"])).decision,
            Decision::Ask,
            "cp out of scratch should ask"
        );

        unsafe {
            match saved {
                Some(v) => std::env::set_var("TOOL_GATES_SCRATCH", v),
                None => std::env::remove_var("TOOL_GATES_SCRATCH"),
            }
        }
    }

    // === rm ===

    #[test]
    fn test_rm_catastrophic_blocks() {
        for path in ["/", "/*", "~", "~/"] {
            let result = check_filesystem(&cmd("rm", &[path]));
            assert_eq!(result.decision, Decision::Block, "Failed for: {path}");
        }
    }

    #[test]
    fn test_rm_normalized_paths_block() {
        // Paths that normalize to root
        for path in ["//", "/./", "///"] {
            let result = check_filesystem(&cmd("rm", &["-rf", path]));
            assert_eq!(result.decision, Decision::Block, "Failed for: {path}");
        }
    }

    #[test]
    fn test_rm_traversal_blocks() {
        let result = check_filesystem(&cmd("rm", &["-rf", "/tmp/../"]));
        assert_eq!(result.decision, Decision::Block);
    }

    #[test]
    fn test_rm_recursive_asks() {
        let result = check_filesystem(&cmd("rm", &["-rf", "dir"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === home-equivalent catastrophic rm forms (plan sites 1, regression guard) ===

    use crate::gates::test_utils::{real_home, real_user};

    #[test]
    fn test_rm_dollar_home_blocks() {
        for arg in ["$HOME", "${HOME}"] {
            let result = check_filesystem(&cmd("rm", &["-rf", arg]));
            assert_eq!(
                result.decision,
                Decision::Block,
                "rm -rf {arg} should block"
            );
        }
    }

    #[test]
    fn test_rm_absolute_home_blocks() {
        let home = real_home();
        for path in [home.clone(), format!("{home}/"), format!("{home}/*")] {
            let result = check_filesystem(&cmd("rm", &["-rf", &path]));
            assert_eq!(
                result.decision,
                Decision::Block,
                "rm -rf {path} should block"
            );
        }
    }

    #[test]
    fn test_rm_home_user_var_blocks() {
        let user = real_user();
        for path in [
            format!("/home/{user}"),
            format!("/home/{user}/"),
            "/home/$USER".to_string(),
            "/home/${USER}".to_string(),
        ] {
            let result = check_filesystem(&cmd("rm", &["-rf", &path]));
            assert_eq!(
                result.decision,
                Decision::Block,
                "rm -rf {path} should block"
            );
        }
    }

    #[test]
    fn test_rm_security_dotdir_blocks() {
        let home = real_home();
        let forms = [
            "~/.ssh".to_string(),
            "~/.gnupg".to_string(),
            "$HOME/.aws".to_string(),
            "${HOME}/.kube".to_string(),
            format!("{home}/.docker"),
            format!("{home}/.config/gh"),
            format!("{home}/.password-store"),
            format!("{home}/.vault-token"),
        ];
        for arg in forms {
            let result = check_filesystem(&cmd("rm", &["-rf", &arg]));
            assert_eq!(
                result.decision,
                Decision::Block,
                "rm -rf {arg} should block (security dotdir)"
            );
        }
    }

    #[test]
    fn test_rm_benign_paths_still_ask() {
        // Subdirectories under home that are NOT security-critical must
        // still be ask (not block), so legitimate project cleanup works.
        let home = real_home();
        let benign = format!("{home}/projects/foo");
        let result = check_filesystem(&cmd("rm", &["-rf", &benign]));
        assert_eq!(
            result.decision,
            Decision::Ask,
            "rm -rf {benign} should still just ask"
        );
    }

    #[test]
    fn test_rm_security_dotdir_glob_blocks() {
        // The runtime catastrophic set includes both `dir` and `dir/*`
        // forms. Confirm the glob form blocks for every variable shape.
        let forms = [
            "$HOME/.ssh/*",
            "${HOME}/.aws/*",
            "/home/$USER/.gnupg/*",
            "/home/${USER}/.kube/*",
        ];
        for arg in forms {
            let result = check_filesystem(&cmd("rm", &["-rf", arg]));
            assert_eq!(
                result.decision,
                Decision::Block,
                "rm -rf {arg} should block (glob over security dir)"
            );
        }
    }

    #[test]
    fn test_rm_security_dotdir_file_blocks() {
        // Files under a security-critical dotdir must also block, not just
        // the dir itself. Catches paths the runtime catastrophic set
        // doesn't enumerate (e.g. .aws/credentials, .ssh/id_rsa).
        let home = real_home();
        let forms = [
            format!("{home}/.aws/credentials"),
            format!("{home}/.ssh/id_rsa"),
            format!("{home}/.gnupg/private-keys-v1.d/abc.key"),
            format!("{home}/.kube/config"),
            "$HOME/.aws/credentials".to_string(),
            "${HOME}/.ssh/id_ed25519".to_string(),
        ];
        for arg in forms {
            let result = check_filesystem(&cmd("rm", &["-f", &arg]));
            assert_eq!(
                result.decision,
                Decision::Block,
                "rm -f {arg} should block (file under security dir)"
            );
        }
    }

    #[test]
    fn test_rm_multi_arg_blocks_on_any_catastrophic() {
        // check_rm iterates all args. A catastrophic arg anywhere in the
        // arg list must block, even if a benign arg precedes it.
        let result = check_filesystem(&cmd("rm", &["-rf", "file.txt", "$HOME"]));
        assert_eq!(
            result.decision,
            Decision::Block,
            "Multi-arg rm with catastrophic second arg should block"
        );
    }

    #[test]
    fn test_rm_multi_arg_all_benign_asks() {
        // Negative case: multi-arg rm with all benign targets still asks.
        let result = check_filesystem(&cmd("rm", &["-rf", "a.txt", "b.txt", "c.txt"]));
        assert_eq!(
            result.decision,
            Decision::Ask,
            "Multi-arg rm with only benign args should ask, not block"
        );
    }

    #[test]
    fn test_rm_single_file_asks() {
        let result = check_filesystem(&cmd("rm", &["file.txt"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === tar ===

    #[test]
    fn test_tar_list_allows() {
        let allow_cmds = [
            &["-tf", "file.tar"][..],
            &["-tvf", "file.tar"],
            &["--list", "-f", "file.tar"],
        ];

        for args in allow_cmds {
            let result = check_filesystem(&cmd("tar", args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_tar_extract_asks() {
        let ask_cmds = [
            &["-xf", "file.tar"][..],
            &["-xzf", "file.tar.gz"],
            &["--extract", "-f", "file.tar"],
        ];

        for args in ask_cmds {
            let result = check_filesystem(&cmd("tar", args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    // === unzip ===

    #[test]
    fn test_unzip_list_allows() {
        let result = check_filesystem(&cmd("unzip", &["-l", "file.zip"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_unzip_extract_asks() {
        let result = check_filesystem(&cmd("unzip", &["file.zip"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Other ===

    #[test]
    fn test_mv_asks() {
        let result = check_filesystem(&cmd("mv", &["old", "new"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_sed_inplace_asks() {
        let result = check_filesystem(&cmd("sed", &["-i", "s/old/new/", "file"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === rmdir ===

    #[test]
    fn test_rmdir_asks() {
        let result = check_filesystem(&cmd("rmdir", &["/tmp/foo"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_non_filesystem_skips() {
        let result = check_filesystem(&cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}

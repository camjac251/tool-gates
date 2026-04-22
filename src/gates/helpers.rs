//! Common helper functions for gate implementations.
//!
//! These helpers extract common patterns that can't be expressed declaratively.

/// Security-critical paths under the home directory. A recursive `rm` targeting
/// any of these is treated as catastrophic (hard block) rather than just "ask".
///
/// Kept in sync with `BLOCKED_SECURITY_DIRS` in `src/router.rs` — that list
/// governs the broader sensitive-path detector across all commands; this one
/// governs the hard-block decision specifically for `rm`.
pub const BLOCKED_SECURITY_DIRS_UNDER_HOME: &[&str] = &[
    "/.ssh",
    "/.gnupg",
    "/.aws",
    "/.kube",
    "/.docker",
    "/.config/gh",
    "/.password-store",
    "/.vault-token",
];

/// Expand shell-style home/user variables in a path argument.
///
/// Handles exactly these forms, in order:
/// 1. Leading `~/` -> `dirs::home_dir()` + rest
/// 2. Bare `~` -> `dirs::home_dir()`
/// 3. `${HOME}` and bare `$HOME` -> `dirs::home_dir()`
/// 4. `${USER}` and bare `$USER` -> `std::env::var("USER")` (fallback to
///    final component of `dirs::home_dir()`)
///
/// Returns `None` when any recognized variable is present but cannot be
/// resolved from the environment. Callers at security sites MUST treat
/// `None` as "fail closed" (block/deny) rather than substituting the
/// original string.
///
/// Note: on healthy Unix systems this `None` branch is essentially
/// unreachable — `dirs::home_dir()` falls back to libc's `getpwuid_r`
/// when `HOME` is unset, and `resolve_user` falls back to the home dir's
/// basename when `USER` is empty. The branch is genuine defense-in-depth
/// for sandboxed / chroot / no-passwd-entry environments where neither
/// signal is available, and cannot be meaningfully exercised in a unit
/// test without refactoring to inject a resolver.
///
/// The bare `$HOME` / `$USER` forms do NOT partial-match an identifier
/// character: `$HOMEDIR`, `$USERNAME`, `$HOME_BACKUP` are left intact.
///
/// Unrecognized `$FOO` variables are left intact and do not trigger the
/// fail-closed signal.
pub fn expand_path_vars(arg: &str) -> Option<String> {
    let mut s = String::with_capacity(arg.len());

    // Step 1+2: leading tilde forms (whole-arg case).
    if arg == "~" {
        let home = dirs::home_dir()?;
        return Some(home.to_string_lossy().into_owned());
    }
    if let Some(rest) = arg.strip_prefix("~/") {
        let home = dirs::home_dir()?;
        s.push_str(&home.to_string_lossy());
        s.push('/');
        s.push_str(rest);
    } else {
        s.push_str(arg);
    }

    // Step 2b: word-boundary `~/` for embedded use (e.g., settings patterns
    // like `Bash(mytool run ~/scripts/*)`). POSIX tilde expansion happens at
    // word boundaries, so we replace ` ~/` and `\t~/` occurrences after the
    // leading-tilde branch above has already resolved any prefix form.
    if s.contains(" ~/") || s.contains("\t~/") {
        let home = dirs::home_dir()?;
        let home_str = home.to_string_lossy();
        s = s.replace(" ~/", &format!(" {home_str}/"));
        s = s.replace("\t~/", &format!("\t{home_str}/"));
    }

    // Step 3+4: $HOME / $USER variable substitution. Braced first so `$HOME`
    // cannot partially consume the token inside `${HOME}`.
    if s.contains('$') {
        // Braced variants: literal string replacement is safe because the
        // braces terminate the token unambiguously.
        if s.contains("${HOME}") {
            let home = dirs::home_dir()?;
            s = s.replace("${HOME}", &home.to_string_lossy());
        }
        if s.contains("${USER}") {
            let user = resolve_user()?;
            s = s.replace("${USER}", &user);
        }

        // Bare variants: need a word-boundary check so `$HOMEDIR`,
        // `$USERNAME`, `$HOME_OLD` are NOT expanded.
        if contains_bare_var(&s, "$HOME") {
            let home = dirs::home_dir()?;
            s = replace_bare_var(&s, "$HOME", &home.to_string_lossy());
        }
        if contains_bare_var(&s, "$USER") {
            let user = resolve_user()?;
            s = replace_bare_var(&s, "$USER", &user);
        }
    }

    Some(s)
}

/// Convenience wrapper: returns the expanded form or the original string.
/// Use only at non-security sites where passthrough on unresolved vars is
/// the safer behavior (e.g., settings.json pattern matching, where a
/// non-matching pattern is equivalent to "no rule").
pub fn expand_path_vars_lossy(arg: &str) -> String {
    expand_path_vars(arg).unwrap_or_else(|| arg.to_string())
}

fn resolve_user() -> Option<String> {
    if let Ok(u) = std::env::var("USER") {
        if !u.is_empty() {
            return Some(u);
        }
    }
    // Fallback: final path component of home dir.
    dirs::home_dir().and_then(|h| h.file_name().map(|n| n.to_string_lossy().into_owned()))
}

/// True iff `var` appears in `s` and is NOT immediately followed by a
/// word character (`[A-Za-z0-9_]`).
fn contains_bare_var(s: &str, var: &str) -> bool {
    let bytes = s.as_bytes();
    let mut start = 0;
    while let Some(idx) = s[start..].find(var) {
        let abs = start + idx;
        let after = abs + var.len();
        let is_boundary = bytes
            .get(after)
            .is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'_'));
        if is_boundary {
            return true;
        }
        start = after;
    }
    false
}

/// Replace every word-boundary-terminated occurrence of `var` in `s` with
/// `replacement`. Leaves `$HOMEDIR`-style tokens unchanged.
fn replace_bare_var(s: &str, var: &str, replacement: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0;
    while let Some(idx) = s[cursor..].find(var) {
        let abs = cursor + idx;
        let after = abs + var.len();
        let is_boundary = bytes
            .get(after)
            .is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'_'));
        out.push_str(&s[cursor..abs]);
        if is_boundary {
            out.push_str(replacement);
        } else {
            out.push_str(var);
        }
        cursor = after;
    }
    out.push_str(&s[cursor..]);
    out
}

/// Extract the value of a flag from command arguments.
///
/// Handles multiple formats:
/// - `-X value` (short flag with space)
/// - `-Xvalue` (short flag combined)
/// - `--flag value` (long flag with space)
/// - `--flag=value` (long flag with equals)
///
/// # Example
/// ```ignore
/// let args = vec!["-X".to_string(), "POST".to_string()];
/// assert_eq!(get_flag_value(&args, &["-X", "--request"]), Some("POST"));
/// ```
pub fn get_flag_value<'a>(args: &'a [String], flags: &[&str]) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        for flag in flags {
            // Long flag with equals: --request=POST
            if let Some(value) = arg.strip_prefix(&format!("{}=", flag)) {
                return Some(value);
            }

            // Exact match with next arg: -X POST or --request POST
            if arg == *flag && i + 1 < args.len() {
                return Some(&args[i + 1]);
            }

            // Short flag combined: -XPOST (only for single-char flags)
            if flag.len() == 2 && flag.starts_with('-') && !flag.starts_with("--") {
                if let Some(value) = arg.strip_prefix(flag) {
                    if !value.is_empty() {
                        return Some(value);
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Normalize a path for security checking.
///
/// Collapses multiple slashes, removes trailing slashes and dots.
/// Used to detect path traversal attempts like `//`, `/./`, etc.
///
/// # Example
/// ```ignore
/// assert_eq!(normalize_path("//"), "/");
/// assert_eq!(normalize_path("/./"), "/");
/// assert_eq!(normalize_path("/tmp/../"), "/tmp/..");
/// ```
pub fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    // Collapse multiple slashes
    let mut result: String = path.chars().fold(String::new(), |mut acc, c| {
        if c == '/' && acc.ends_with('/') {
            // Skip duplicate slash
        } else {
            acc.push(c);
        }
        acc
    });

    // Remove trailing /. sequences and trailing slashes
    loop {
        if result.ends_with("/.") {
            result.truncate(result.len() - 2);
        } else if result.len() > 1 && result.ends_with('/') {
            result.pop();
        } else {
            break;
        }
    }

    // Empty result from root path normalization should become /
    if result.is_empty() {
        return "/".to_string();
    }

    result
}

/// Check if a path contains suspicious traversal patterns.
///
/// Returns true if the path could potentially traverse to sensitive locations.
pub fn is_suspicious_path(path: &str) -> bool {
    // Absolute path with .. could reach root
    if path.starts_with('/') && path.contains("..") {
        return true;
    }
    false
}

/// Check if command has any of the specified flags.
pub fn has_any_flag(args: &[String], flags: &[&str]) -> bool {
    args.iter().any(|a| flags.contains(&a.as_str()))
}

/// Find the first `http(s)://` URL in a list of command arguments.
///
/// Strips a single pair of surrounding quotes if present (bash parsing already
/// drops shell quotes, but `xh` / `curl` copy-pastes sometimes include them
/// inside a single quoted token).
pub fn find_http_url(args: &[String]) -> Option<&str> {
    args.iter().find_map(|a| {
        let s = a.trim_matches(|c| c == '"' || c == '\'');
        if s.starts_with("http://") || s.starts_with("https://") {
            Some(s)
        } else {
            None
        }
    })
}

/// Return true when `url` points at GitHub-hosted file content or metadata
/// that `gh api` would serve more reliably (auth, rate limits, private repos).
///
/// Covered shapes:
/// - `raw.githubusercontent.com/*`
/// - `gist.githubusercontent.com/*`
/// - `api.github.com/*`
/// - `github.com/OWNER/REPO/{blob,raw}/*`
///
/// Regular `github.com/OWNER/REPO` landing pages are intentionally NOT matched
/// here - those are fine to view in a browser or hand to a user-facing tool.
pub fn is_github_content_url(url: &str) -> bool {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = after_scheme.split('/').next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);

    match host {
        "raw.githubusercontent.com" | "gist.githubusercontent.com" | "api.github.com" => true,
        "github.com" | "www.github.com" => {
            let path = after_scheme.split_once('/').map(|(_, p)| p).unwrap_or("");
            let mut parts = path.splitn(4, '/');
            let (_, _, segment) = (parts.next(), parts.next(), parts.next());
            matches!(segment, Some("blob") | Some("raw"))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === get_flag_value ===

    #[test]
    fn test_get_flag_value_short_space() {
        let args: Vec<String> = vec!["-X", "POST", "http://example.com"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(get_flag_value(&args, &["-X", "--request"]), Some("POST"));
    }

    #[test]
    fn test_get_flag_value_short_combined() {
        let args: Vec<String> = vec!["-XPOST", "http://example.com"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(get_flag_value(&args, &["-X", "--request"]), Some("POST"));
    }

    #[test]
    fn test_get_flag_value_long_space() {
        let args: Vec<String> = vec!["--request", "PUT", "http://example.com"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(get_flag_value(&args, &["-X", "--request"]), Some("PUT"));
    }

    #[test]
    fn test_get_flag_value_long_equals() {
        let args: Vec<String> = vec!["--request=DELETE", "http://example.com"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(get_flag_value(&args, &["-X", "--request"]), Some("DELETE"));
    }

    #[test]
    fn test_get_flag_value_not_found() {
        let args: Vec<String> = vec!["http://example.com"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(get_flag_value(&args, &["-X", "--request"]), None);
    }

    // === normalize_path ===

    #[test]
    fn test_normalize_path_double_slash() {
        assert_eq!(normalize_path("//"), "/");
        assert_eq!(normalize_path("///"), "/");
    }

    #[test]
    fn test_normalize_path_trailing_dot() {
        assert_eq!(normalize_path("/./"), "/");
        assert_eq!(normalize_path("/tmp/."), "/tmp");
    }

    #[test]
    fn test_normalize_path_trailing_slash() {
        assert_eq!(normalize_path("/tmp/"), "/tmp");
    }

    #[test]
    fn test_normalize_path_normal() {
        assert_eq!(normalize_path("/tmp/foo"), "/tmp/foo");
    }

    // === is_suspicious_path ===

    #[test]
    fn test_suspicious_path_traversal() {
        assert!(is_suspicious_path("/tmp/../etc/passwd"));
        assert!(is_suspicious_path("/.."));
    }

    #[test]
    fn test_suspicious_path_safe() {
        assert!(!is_suspicious_path("/tmp/foo"));
        assert!(!is_suspicious_path("../relative")); // Not absolute, not suspicious
    }

    // === expand_path_vars ===

    use crate::gates::test_utils::{real_home, real_user};

    #[test]
    fn test_expand_path_vars_tilde_root() {
        assert_eq!(expand_path_vars("~"), Some(real_home()));
    }

    #[test]
    fn test_expand_path_vars_tilde_slash() {
        let got = expand_path_vars("~/.ssh").unwrap();
        assert_eq!(got, format!("{}/.ssh", real_home()));
    }

    #[test]
    fn test_expand_path_vars_dollar_home_bare() {
        let got = expand_path_vars("$HOME/.aws/credentials").unwrap();
        assert_eq!(got, format!("{}/.aws/credentials", real_home()));
    }

    #[test]
    fn test_expand_path_vars_dollar_home_braced() {
        let got = expand_path_vars("${HOME}/.kube/config").unwrap();
        assert_eq!(got, format!("{}/.kube/config", real_home()));
    }

    #[test]
    fn test_expand_path_vars_dollar_user_bare() {
        let got = expand_path_vars("/home/$USER/.ssh").unwrap();
        assert_eq!(got, format!("/home/{}/.ssh", real_user()));
    }

    #[test]
    fn test_expand_path_vars_dollar_user_braced() {
        let got = expand_path_vars("/home/${USER}/.ssh").unwrap();
        assert_eq!(got, format!("/home/{}/.ssh", real_user()));
    }

    #[test]
    fn test_expand_path_vars_literal_path_unchanged() {
        assert_eq!(
            expand_path_vars("/etc/passwd"),
            Some("/etc/passwd".to_string())
        );
    }

    #[test]
    fn test_expand_path_vars_no_partial_match() {
        // $HOMEDIR, $HOME_OLD, $USERNAME must NOT be expanded.
        assert_eq!(
            expand_path_vars("$HOMEDIR/foo"),
            Some("$HOMEDIR/foo".to_string())
        );
        assert_eq!(expand_path_vars("$HOME_OLD"), Some("$HOME_OLD".to_string()));
        assert_eq!(
            expand_path_vars("$USERNAME/bin"),
            Some("$USERNAME/bin".to_string())
        );
    }

    #[test]
    fn test_expand_path_vars_unrecognized_var_passthrough() {
        // $UNDEFINED is not a recognized token. Passthrough is the correct
        // behavior; only *recognized* vars that can't resolve trigger None.
        assert_eq!(
            expand_path_vars("$UNDEFINED/.ssh"),
            Some("$UNDEFINED/.ssh".to_string())
        );
    }

    #[test]
    fn test_expand_path_vars_multiple_occurrences() {
        let got = expand_path_vars("$HOME:$HOME/bin").unwrap();
        let h = real_home();
        assert_eq!(got, format!("{h}:{h}/bin"));
    }

    #[test]
    fn test_expand_path_vars_mixed_forms() {
        let got = expand_path_vars("${HOME}/projects/$USER-app").unwrap();
        assert_eq!(got, format!("{}/projects/{}-app", real_home(), real_user()));
    }

    #[test]
    fn test_expand_path_vars_lossy_passthrough() {
        // Lossy variant returns original on passthrough (not None).
        assert_eq!(expand_path_vars_lossy("$UNDEFINED"), "$UNDEFINED");
        assert_eq!(expand_path_vars_lossy("/etc/hosts"), "/etc/hosts");
    }

    #[test]
    fn test_expand_path_vars_trailing_slash_preserved() {
        // Callers outside check_rm don't normalize, so the trailing slash
        // must survive expansion.
        let got = expand_path_vars("${HOME}/").unwrap();
        assert_eq!(got, format!("{}/", real_home()));
    }

    #[test]
    fn test_expand_path_vars_mid_token_unchanged() {
        // Mid-token vars are documented out of scope. This test pins the
        // current safe behavior: leave mid-token forms untouched rather
        // than partial-expanding into something surprising.
        // `foo$HOMEbar` is bare $HOME followed by `bar` (a word char), so
        // the word-boundary check leaves the whole token intact.
        assert_eq!(
            expand_path_vars("foo$HOMEbar"),
            Some("foo$HOMEbar".to_string())
        );
    }

    /// Empty `$USER` falls back to home-dir basename. This is the only piece
    /// of `resolve_user` we can observe without breaking the libc passwd
    /// fallback. Serialized because mutating env vars races other tests.
    #[serial_test::serial]
    #[test]
    fn test_resolve_user_falls_back_when_user_empty() {
        let saved = std::env::var("USER").ok();
        // SAFETY: serialized via #[serial], so no concurrent env access.
        unsafe {
            std::env::set_var("USER", "");
        }

        let got = expand_path_vars("/home/$USER/.ssh").unwrap();
        let expected_basename = dirs::home_dir()
            .and_then(|h| h.file_name().map(|n| n.to_string_lossy().into_owned()))
            .expect("home dir basename must resolve");
        assert_eq!(got, format!("/home/{expected_basename}/.ssh"));

        // Restore so the rest of the suite sees the original env.
        unsafe {
            match saved {
                Some(v) => std::env::set_var("USER", v),
                None => std::env::remove_var("USER"),
            }
        }
    }

    // === has_any_flag ===

    #[test]
    fn test_has_any_flag() {
        let args: Vec<String> = vec!["--dry-run", "deploy"]
            .into_iter()
            .map(String::from)
            .collect();
        assert!(has_any_flag(&args, &["--dry-run", "-n"]));
        assert!(!has_any_flag(&args, &["--force", "-f"]));
    }

    // === find_http_url ===

    fn to_args(vs: &[&str]) -> Vec<String> {
        vs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_find_http_url_positional() {
        let args = to_args(&["-sL", "https://example.com/path"]);
        assert_eq!(find_http_url(&args), Some("https://example.com/path"));
    }

    #[test]
    fn test_find_http_url_strips_quotes() {
        let args = to_args(&["\"https://example.com/path\""]);
        assert_eq!(find_http_url(&args), Some("https://example.com/path"));
    }

    #[test]
    fn test_find_http_url_none() {
        let args = to_args(&["-sL", "/tmp/file"]);
        assert_eq!(find_http_url(&args), None);
    }

    // === is_github_content_url ===

    #[test]
    fn test_is_github_content_url_raw() {
        assert!(is_github_content_url(
            "https://raw.githubusercontent.com/OWNER/REPO/main/file"
        ));
    }

    #[test]
    fn test_is_github_content_url_gist_raw() {
        assert!(is_github_content_url(
            "https://gist.githubusercontent.com/OWNER/ID/raw/HASH/file"
        ));
    }

    #[test]
    fn test_is_github_content_url_api() {
        assert!(is_github_content_url(
            "https://api.github.com/repos/OWNER/REPO/contents/path"
        ));
    }

    #[test]
    fn test_is_github_content_url_blob_form() {
        assert!(is_github_content_url(
            "https://github.com/OWNER/REPO/blob/main/path/to/file"
        ));
    }

    #[test]
    fn test_is_github_content_url_raw_form() {
        assert!(is_github_content_url(
            "https://github.com/OWNER/REPO/raw/main/path/to/file"
        ));
    }

    #[test]
    fn test_is_github_content_url_www_blob_form() {
        assert!(is_github_content_url(
            "https://www.github.com/OWNER/REPO/blob/main/f"
        ));
    }

    #[test]
    fn test_is_github_content_url_landing_page_is_not_content() {
        assert!(!is_github_content_url("https://github.com/OWNER/REPO"));
    }

    #[test]
    fn test_is_github_content_url_other_host() {
        assert!(!is_github_content_url("https://example.com/OWNER/REPO"));
        assert!(!is_github_content_url(
            "https://githubusercontent.example.com/x"
        ));
    }

    #[test]
    fn test_is_github_content_url_handles_port_and_userinfo() {
        assert!(is_github_content_url(
            "https://user@api.github.com:443/repos/OWNER/REPO"
        ));
    }
}

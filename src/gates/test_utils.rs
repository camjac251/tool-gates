//! Test utilities for gate tests.

use crate::models::CommandInfo;

/// Create a CommandInfo for testing.
///
/// # Example
/// ```ignore
/// use crate::gates::test_utils::cmd;
///
/// let info = cmd("git", &["status"]);
/// assert_eq!(info.program, "git");
/// assert_eq!(info.args, vec!["status"]);
/// ```
pub fn cmd(program: &str, args: &[&str]) -> CommandInfo {
    CommandInfo {
        raw: format!("{} {}", program, args.join(" ")),
        program: program.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
    }
}

/// Resolve the test process's home directory as a string.
///
/// Panics if `dirs::home_dir()` returns None — the test environment must have
/// HOME set. Use this helper instead of duplicating the resolution boilerplate.
pub fn real_home() -> String {
    dirs::home_dir()
        .expect("HOME must be set for these tests")
        .to_string_lossy()
        .into_owned()
}

/// Resolve the test process's username, falling back to the final component
/// of the home directory if `$USER` is unset or empty (matches `resolve_user`
/// in `helpers.rs`).
pub fn real_user() -> String {
    std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty())
        .or_else(|| {
            dirs::home_dir().and_then(|h| h.file_name().map(|n| n.to_string_lossy().into_owned()))
        })
        .expect("USER or HOME basename must resolve for these tests")
}

//! Scratch-directory resolution: recognize and canonicalize write targets
//! under `$TOOL_GATES_SCRATCH` so they can be auto-allowed.

use crate::paths::{is_under_any_dir, resolve_path};
use regex::Regex;
use std::sync::LazyLock;

/// `$NAME` / `${NAME}` parameter-expansion token, for substituting tracked
/// scratch variables into a write target. Group 1 is the braced name, group 2
/// the bare name. `${PWD//x/y}` (operator expansion) does not match because no
/// `}` follows the name, so it is left literal.
static SCRATCH_VAR_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{(\w+)\}|\$(\w+)").expect("SCRATCH_VAR_TOKEN_RE must compile")
});

/// `$CLAUDE_CODE_SESSION_ID` token in its three surface forms: bare
/// `$CLAUDE_CODE_SESSION_ID` (word-bounded so a longer name is not partially
/// consumed), braced `${CLAUDE_CODE_SESSION_ID}`, and the default form
/// `${CLAUDE_CODE_SESSION_ID:-fallback}` (group 1 captures the literal
/// fallback). Used to resolve the canonical scratchpad session segment so the
/// residual-expansion guard does not reject the documented convention path.
static SESSION_ID_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{CLAUDE_CODE_SESSION_ID(?::-([^}]*))?\}|\$CLAUDE_CODE_SESSION_ID\b")
        .expect("SESSION_ID_TOKEN_RE must compile")
});

/// True when a normalized scratch base is too broad to auto-allow writes under.
/// `scratch_base` rejects such a base (returns `None`, fail closed) so a
/// misconfigured `TOOL_GATES_SCRATCH` cannot turn the scratch exemption into a
/// universal write allowance via `is_under_any_dir`'s prefix match. The default
/// `~/.cache/tool-gates-scratch` is nested deeply enough to always pass.
fn is_unsafe_scratch_base(base: &str) -> bool {
    use std::path::{Component, Path};

    // Empty (what `/` normalizes-and-trims to) or an explicit root.
    if base.is_empty() || base == "/" {
        return true;
    }
    // The user's home directory itself: a base of `/home/<user>` would
    // auto-allow ~/.ssh, ~/.aws, ~/.config, etc.
    if let Some(home) = dirs::home_dir()
        && Path::new(base) == home.as_path()
    {
        return true;
    }
    // Too shallow to be a real scratch dir: depth < 2 covers every bare
    // top-level dir (`/home`, `/etc`, `/usr`, `/var`, `/tmp`, ...).
    Path::new(base)
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count()
        < 2
}

pub fn scratch_base() -> Option<String> {
    let raw = match std::env::var("TOOL_GATES_SCRATCH") {
        Ok(v) if !v.trim().is_empty() => crate::gates::helpers::expand_path_vars(v.trim())?,
        _ => dirs::home_dir()?
            .join(".cache")
            .join("tool-gates-scratch")
            .to_string_lossy()
            .into_owned(),
    };
    let normalized = crate::gates::helpers::normalize_path(&raw)
        .trim_end_matches('/')
        .to_string();
    // Fail closed on a base too broad to safely auto-allow writes under (`/`,
    // `/home`, the home dir, a bare system root). Otherwise is_under_scratch
    // would match nearly every absolute path and bypass the credential /
    // file-guard floor.
    if is_unsafe_scratch_base(&normalized) {
        return None;
    }
    Some(normalized)
}

/// True when `path` resolves under one of the two recognized scratch roots:
/// the `$TOOL_GATES_SCRATCH` base (any client), or the current Claude Code
/// session's native scratchpad under the system temp dir (see
/// `is_claude_session_scratchpad`).
///
/// Accepts the surface forms an agent actually produces, since tool-gates does
/// not expand arbitrary environment variables out of a raw command string:
/// - the literal `$TOOL_GATES_SCRATCH/...` / `${TOOL_GATES_SCRATCH}/...` token
///   (only while the env var is set; unset, the shell expands the token to
///   nothing, so the gate refuses to substitute its internal default),
/// - the `~/.cache/tool-gates-scratch/...` tilde form,
/// - an already-absolute path,
/// - the canonical scratchpad convention tokens `${PWD//\//-}` and
///   `$CLAUDE_CODE_SESSION_ID` (resolved below so the convention stays
///   friction-free).
///
/// The target is canonicalized (`resolve_path`) before the prefix check, so a
/// symlink inside the scratch tree that points elsewhere, or a `..` escape,
/// does not match.
///
/// Fail-closed guard: any parameter expansion the gate could not resolve to a
/// concrete value (`$X`, `${X}`, `${X:-..}`, `$(...)`, backticks) is left
/// literal by the substitutions above. The shell will expand it to something
/// the gate never saw, possibly climbing out of the base with `..`, while the
/// lexical/canonical check would treat the literal token as a benign path
/// segment and wrongly auto-allow. So a candidate that still carries an
/// unresolved expansion is never reported as scratch; normal gating prompts
/// instead.
pub fn is_under_scratch(path: &str) -> bool {
    let base = scratch_base();
    // Substitute the literal TOOL_GATES_SCRATCH token (braced first) before the
    // generic ~/$HOME expansion, and only while the env var is actually set:
    // the shell expands the token from the same env, so with it unset the
    // shell produces "" while the internal default base would still
    // prefix-match here and auto-allow a write the shell sends somewhere
    // else. Left literal, the token is rejected by the residual guard below.
    // An unresolvable base (None) gets the same treatment.
    let token_env_set = std::env::var("TOOL_GATES_SCRATCH").is_ok_and(|v| !v.trim().is_empty());
    let substituted = match base.as_deref() {
        Some(base) if token_env_set => path
            .replace("${TOOL_GATES_SCRATCH}", base)
            .replace("$TOOL_GATES_SCRATCH", base),
        _ => path.to_string(),
    };
    // Resolve the scratch-convention tokens to the same values the shell will:
    // the gate's own environment carries the session id the Bash subprocess
    // expands `$CLAUDE_CODE_SESSION_ID` to, and `${PWD//\//-}` is traversal-safe
    // by construction (a global slash replacement cannot emit `/` or `..`).
    let session_id = std::env::var("CLAUDE_CODE_SESSION_ID").ok();
    let pwd = std::env::var("PWD").ok();
    let substituted =
        resolve_scratch_convention_tokens(&substituted, session_id.as_deref(), pwd.as_deref());
    let expanded = crate::gates::helpers::expand_path_vars_lossy(&substituted);
    if path_has_unresolved_expansion(&expanded) {
        return false;
    }
    let resolved = resolve_path(&expanded);
    if let Some(base) = &base
        && is_under_any_dir(&resolved, std::slice::from_ref(base))
    {
        return true;
    }
    is_claude_session_scratchpad(&resolved)
}

/// True when `resolved` (already substituted, expansion-guarded, and
/// canonicalized by `is_under_scratch`) targets the current session's Claude
/// Code scratchpad: `<tmpdir>/claude-<uid>/<project-segment>/<session-id>/scratchpad[/...]`.
///
/// Claude Code creates that directory at session start and hands the agent
/// the literal path in its system prompt, but its own auto-allow covers only
/// the file-tool read/write resolvers; Bash writes into it (redirects, mkdir,
/// tee, cp) would prompt without this check.
///
/// `<project-segment>` encodes the session's launch directory, which can
/// differ from any cwd the gate sees (worktrees, `cd`), and its over-length
/// form carries a hash suffix the gate cannot reproduce. So that segment is
/// matched structurally: exactly one path component of the sanitized alphabet
/// `[A-Za-z0-9-]`. The binding that scopes the match to this session is the
/// `<session-id>` component, which must equal the gate's own
/// `CLAUDE_CODE_SESSION_ID` (the same trusted env source the convention-token
/// resolver uses; for a Bash command the gate and the shell share that env).
/// Other clients never set the variable, so this root is inert for them.
/// Every failure mode falls through to a normal prompt, never to an
/// over-allow.
fn is_claude_session_scratchpad(resolved: &str) -> bool {
    // Session-id gate first: absent or non-UUID means this is not a Claude
    // session. Checking it before touching the filesystem also keeps targets
    // without an OS temp dir (wasm) from reaching temp_dir(), which panics
    // there.
    let Ok(session_id) = std::env::var("CLAUDE_CODE_SESSION_ID") else {
        return false;
    };
    if !is_uuid_shaped(&session_id) {
        return false;
    }
    let root = claude_scratchpad_root();
    let root = root.to_string_lossy();
    let Some(rest) = resolved
        .strip_prefix(root.as_ref())
        .and_then(|r| r.strip_prefix('/'))
    else {
        return false;
    };
    let mut parts = rest.split('/');
    let project_segment_ok = parts.next().is_some_and(|seg| {
        !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    project_segment_ok
        && parts.next() == Some(session_id.as_str())
        && parts.next() == Some("scratchpad")
}

/// Claude Code's per-user tree under the system temp dir, in canonical form
/// (macOS `/tmp` and `$TMPDIR` are symlinks); the candidate side of the
/// scratchpad check is canonicalized the same way by `resolve_path`.
///
/// Must not be called on wasm targets: `temp_dir()` panics there. Callers
/// gate on `CLAUDE_CODE_SESSION_ID` first (always absent on wasm), which is
/// why `is_claude_session_scratchpad` checks the session id before this.
pub fn claude_scratchpad_root() -> std::path::PathBuf {
    let tmp = std::env::temp_dir();
    let tmp = std::fs::canonicalize(&tmp).unwrap_or(tmp);
    tmp.join(claude_tmp_dir_name())
}

/// Directory name of Claude Code's per-user tree under the system temp dir:
/// `claude-<uid>` on unix, an unsuffixed `claude` on Windows. The Windows arm
/// documents the naming but is a fail-closed placeholder: the scratchpad
/// matcher splits on `/`, which Windows backslash paths never satisfy.
#[cfg(unix)]
fn claude_tmp_dir_name() -> String {
    // SAFETY: getuid reads the process credential and cannot fail.
    format!("claude-{}", unsafe { libc::getuid() })
}

#[cfg(windows)]
fn claude_tmp_dir_name() -> String {
    "claude".to_string()
}

#[cfg(not(any(unix, windows)))]
fn claude_tmp_dir_name() -> String {
    "claude-0".to_string()
}

/// Strict UUID shape: 36 chars, dashes at 8/13/18/23, hex digits elsewhere.
/// Guards the session-id path component against a degenerate or hostile env
/// value (empty string, `..`, a path fragment) widening the scratchpad match.
fn is_uuid_shaped(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    s.bytes().enumerate().all(|(i, b)| match i {
        8 | 13 | 18 | 23 => b == b'-',
        _ => b.is_ascii_hexdigit(),
    })
}

/// Variable-aware scratch check: substitute tracked `$NAME`/`${NAME}` tokens in
/// `arg` using `vars`, then run the canonicalize-then-prefix `is_under_scratch`
/// on the result. Promotes a variable-indirected write
/// (`S=$TOOL_GATES_SCRATCH/x; mkdir "$S"`) to the same decision as the inline
/// form. The substituted path still goes through the full canonicalization, so
/// an escape (`$S/../../etc`) or a value that does not resolve under the base is
/// never auto-allowed; only the existing guarantees are widened to reach
/// through a variable.
pub fn is_under_scratch_with_vars(
    arg: &str,
    vars: &std::collections::HashMap<String, String>,
) -> bool {
    if vars.is_empty() {
        return is_under_scratch(arg);
    }
    is_under_scratch(&substitute_scratch_vars(arg, vars))
}

/// Substitute `$NAME` / `${NAME}` tokens in `arg` using `vars`, resolving
/// transitively (a tracked value may reference another tracked var) with a
/// small iteration cap that also breaks any reference cycle. Names not in the
/// map (including `$TOOL_GATES_SCRATCH`, `$HOME`, `$USER`, and operator
/// expansions like `${PWD//x/y}`) are left intact for `is_under_scratch` to
/// handle.
fn substitute_scratch_vars(arg: &str, vars: &std::collections::HashMap<String, String>) -> String {
    let mut current = arg.to_string();
    for _ in 0..8 {
        let next = SCRATCH_VAR_TOKEN_RE
            .replace_all(&current, |caps: &regex::Captures| {
                let name = caps
                    .get(1)
                    .or_else(|| caps.get(2))
                    .map(|m| m.as_str())
                    .unwrap_or("");
                match vars.get(name) {
                    Some(v) => v.clone(),
                    None => caps
                        .get(0)
                        .map_or(String::new(), |m| m.as_str().to_string()),
                }
            })
            .into_owned();
        if next == current {
            break;
        }
        current = next;
    }
    current
}

/// Resolve the scratch-convention parameter expansions the gate can map to a
/// concrete, traversal-safe value, so the canonical scratchpad path
/// `$TOOL_GATES_SCRATCH/${PWD//\//-}/$CLAUDE_CODE_SESSION_ID/...` stays
/// friction-free even with the residual-expansion guard active.
///
/// - `${PWD//\//-}` (and the `_`-replacement and unescaped `${PWD///-}`
///   variants): a global slash replacement provably cannot emit a `/` or `..`,
///   so it is traversal-safe regardless of the actual `PWD`. Mapped to the real
///   per-project slug when `pwd` is known, else a fixed safe placeholder; the
///   exact text is immaterial to the under-base check since any slash-free
///   segment stays under the base.
/// - `$CLAUDE_CODE_SESSION_ID` / `${CLAUDE_CODE_SESSION_ID}` /
///   `${CLAUDE_CODE_SESSION_ID:-default}`: the session id. The gate's own
///   environment carries the same value the Bash subprocess expands it to. The
///   `:-default` form falls back to its literal default when the id is absent;
///   the bare/braced forms with no id are left intact for the residual guard.
///
/// Anything not listed here is deliberately left untouched so the residual
/// guard in `is_under_scratch` can reject it.
fn resolve_scratch_convention_tokens(
    s: &str,
    session_id: Option<&str>,
    pwd: Option<&str>,
) -> String {
    let mut out = s.to_string();

    if out.contains("${PWD//") {
        let slug = pwd
            .map(|p| p.trim_start_matches('/').replace('/', "-"))
            .filter(|slug| !slug.is_empty())
            .unwrap_or_else(|| "pwd".to_string());
        for token in ["${PWD//\\//-}", "${PWD//\\//_}", "${PWD///-}", "${PWD///_}"] {
            out = out.replace(token, &slug);
        }
    }

    if out.contains("CLAUDE_CODE_SESSION_ID") {
        let sid = session_id.filter(|id| !id.is_empty());
        out = SESSION_ID_TOKEN_RE
            .replace_all(&out, |caps: &regex::Captures| match sid {
                Some(id) => id.to_string(),
                // No id: only the `${..:-default}` form is resolvable; other
                // forms stay intact so the residual guard fails closed.
                None => caps.get(1).map_or_else(
                    || caps[0].to_string(),
                    |fallback| fallback.as_str().to_string(),
                ),
            })
            .into_owned();
    }

    out
}

/// True when `s` still contains a parameter expansion or command substitution
/// the gate did not resolve: `$NAME`, `${...}`, `$(...)`, a positional/special
/// param (`$1`, `$@`, ...), or a backtick. Such a token will be expanded by the
/// shell to text the gate never inspected, so a scratch-relative path carrying
/// one cannot be proven to stay under the base and must not auto-allow.
///
/// A bare `$` not starting an expansion (e.g. a literal `$` in a filename) does
/// not count; at worst such a path falls through to a prompt, the safe
/// direction.
fn path_has_unresolved_expansion(s: &str) -> bool {
    if s.contains('`') {
        return true;
    }
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'$' {
            continue;
        }
        match bytes.get(i + 1) {
            Some(&next)
                if next == b'{'
                    || next == b'('
                    || next == b'_'
                    || next.is_ascii_alphanumeric()
                    || matches!(next, b'?' | b'@' | b'!' | b'#' | b'*') =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::models::*;
    #[allow(unused_imports)]
    use crate::parser::*;
    #[allow(unused_imports)]
    use crate::router::tests::{get_claude_wire_decision, get_decision, get_reason};
    #[allow(unused_imports)]
    use crate::router::*;
    #[allow(unused_imports)]
    use crate::{
        accept_edits::*, paths::*, pipe_caps::*, scratch::*, security_floor::*, task_expansion::*,
    };

    // === scratch dir recognition ===

    #[serial_test::serial]
    #[test]
    fn test_is_under_scratch_recognizes_forms() {
        let saved = std::env::var("TOOL_GATES_SCRATCH").ok();
        // SAFETY: serialized via #[serial], so no concurrent env access.
        unsafe {
            std::env::set_var("TOOL_GATES_SCRATCH", "/tmp/cc-scratch-test");
        }

        assert!(is_under_scratch("/tmp/cc-scratch-test")); // the base itself
        assert!(is_under_scratch("/tmp/cc-scratch-test/p/s/f.txt"));
        assert!(is_under_scratch("$TOOL_GATES_SCRATCH/p/s/f.txt"));
        assert!(is_under_scratch("${TOOL_GATES_SCRATCH}/f.txt"));

        assert!(!is_under_scratch("/tmp/other/f.txt"));
        assert!(!is_under_scratch("/etc/passwd"));
        // `..` escaping the base is not scratch.
        assert!(!is_under_scratch("/tmp/cc-scratch-test/../escape/f"));
        // Sibling sharing the prefix string but not an actual child.
        assert!(!is_under_scratch("/tmp/cc-scratch-test-evil/f"));

        unsafe {
            match saved {
                Some(v) => std::env::set_var("TOOL_GATES_SCRATCH", v),
                None => std::env::remove_var("TOOL_GATES_SCRATCH"),
            }
        }
    }

    #[serial_test::serial]
    #[test]
    fn test_scratch_token_requires_env() {
        let saved = std::env::var("TOOL_GATES_SCRATCH").ok();
        // SAFETY: serialized via #[serial], so no concurrent env access.
        unsafe {
            std::env::remove_var("TOOL_GATES_SCRATCH");
        }

        // With the env var unset the shell expands the token to "", so the
        // gate must not substitute its internal default; the token path is
        // not scratch and falls to a normal prompt.
        assert!(!is_under_scratch("$TOOL_GATES_SCRATCH/p/f.txt"));
        assert!(!is_under_scratch("${TOOL_GATES_SCRATCH}/p/f.txt"));

        // Fully-spelled paths under the internal default still match: shell
        // and gate agree on those with or without the env var.
        assert!(is_under_scratch("~/.cache/tool-gates-scratch/p/f.txt"));

        unsafe {
            match saved {
                Some(v) => std::env::set_var("TOOL_GATES_SCRATCH", v),
                None => std::env::remove_var("TOOL_GATES_SCRATCH"),
            }
        }
    }

    #[test]
    fn test_is_uuid_shaped() {
        assert!(is_uuid_shaped("01234567-89ab-cdef-0123-456789abcdef"));
        assert!(is_uuid_shaped("ABCDEF01-2345-6789-ABCD-EF0123456789"));

        assert!(!is_uuid_shaped(""));
        assert!(!is_uuid_shaped(".."));
        assert!(!is_uuid_shaped("not-a-uuid"));
        // One char short / long.
        assert!(!is_uuid_shaped("01234567-89ab-cdef-0123-456789abcde"));
        assert!(!is_uuid_shaped("01234567-89ab-cdef-0123-456789abcdef0"));
        // Right length, dashes misplaced or missing.
        assert!(!is_uuid_shaped("0123456789ab-cdef-0123-456789abcdef0"));
        // Non-hex character.
        assert!(!is_uuid_shaped("g1234567-89ab-cdef-0123-456789abcdef"));
        // A path fragment must never pass.
        assert!(!is_uuid_shaped("../../../../../../../../../../etc/pw"));
    }

    #[serial_test::serial]
    #[test]
    fn test_is_under_scratch_recognizes_claude_session_scratchpad() {
        let sid = "01234567-89ab-cdef-0123-456789abcdef";
        let saved_scratch = std::env::var("TOOL_GATES_SCRATCH").ok();
        let saved_sid = std::env::var("CLAUDE_CODE_SESSION_ID").ok();
        // SAFETY: serialized via #[serial], so no concurrent env access.
        unsafe {
            std::env::set_var("TOOL_GATES_SCRATCH", "/tmp/cc-scratch-test");
            std::env::set_var("CLAUDE_CODE_SESSION_ID", sid);
        }

        let root = claude_scratchpad_root();
        let tmp = root
            .parent()
            .expect("tmp parent")
            .to_string_lossy()
            .into_owned();
        let root = root.to_string_lossy().into_owned();
        let pad = format!("{root}/-home-u-proj/{sid}/scratchpad");

        // The scratchpad dir itself, children, and the session-id token form.
        assert!(is_under_scratch(&pad));
        assert!(is_under_scratch(&format!("{pad}/notes.md")));
        assert!(is_under_scratch(&format!("{pad}/sub/dir/f.txt")));
        assert!(is_under_scratch(&format!(
            "{root}/-home-u-proj/$CLAUDE_CODE_SESSION_ID/scratchpad/f.txt"
        )));

        // Another session's scratchpad is not this session's.
        assert!(!is_under_scratch(&format!(
            "{root}/-home-u-proj/99999999-89ab-cdef-0123-456789abcdef/scratchpad/f"
        )));
        // The tasks/ sibling and the session dir itself are outside the
        // scratchpad scope.
        assert!(!is_under_scratch(&format!(
            "{root}/-home-u-proj/{sid}/tasks/t.output"
        )));
        assert!(!is_under_scratch(&format!("{root}/-home-u-proj/{sid}")));
        // `..` collapsing out of the scratchpad is not scratch.
        assert!(!is_under_scratch(&format!("{pad}/../../../../etc/passwd")));
        // An unresolved variable inside stays fail-closed.
        assert!(!is_under_scratch(&format!("{pad}/$X/f")));
        // The project segment must be a single sanitized component.
        assert!(!is_under_scratch(&format!(
            "{root}/bad.segment/{sid}/scratchpad/f"
        )));
        // A different per-user dir under the temp root does not match.
        assert!(!is_under_scratch(&format!(
            "{tmp}/claude-none/-home-u-proj/{sid}/scratchpad/f"
        )));
        // Nor does a same-component extension of the exact root (the prefix
        // strip requires a `/` right after it).
        assert!(!is_under_scratch(&format!(
            "{root}abc/-home-u-proj/{sid}/scratchpad/f"
        )));

        unsafe {
            match saved_scratch {
                Some(v) => std::env::set_var("TOOL_GATES_SCRATCH", v),
                None => std::env::remove_var("TOOL_GATES_SCRATCH"),
            }
            match saved_sid {
                Some(v) => std::env::set_var("CLAUDE_CODE_SESSION_ID", v),
                None => std::env::remove_var("CLAUDE_CODE_SESSION_ID"),
            }
        }
    }

    #[serial_test::serial]
    #[test]
    fn test_claude_scratchpad_requires_uuid_session_id() {
        let saved_scratch = std::env::var("TOOL_GATES_SCRATCH").ok();
        let saved_sid = std::env::var("CLAUDE_CODE_SESSION_ID").ok();
        // SAFETY: serialized via #[serial], so no concurrent env access.
        unsafe {
            std::env::set_var("TOOL_GATES_SCRATCH", "/tmp/cc-scratch-test");
        }

        let root = claude_scratchpad_root().to_string_lossy().into_owned();

        // No session id in the env: the root is inert (non-Claude clients).
        unsafe {
            std::env::remove_var("CLAUDE_CODE_SESSION_ID");
        }
        assert!(!is_under_scratch(&format!(
            "{root}/-home-u-proj/01234567-89ab-cdef-0123-456789abcdef/scratchpad/f"
        )));

        // A non-UUID value never widens the match, even when the path segment
        // matches it exactly.
        unsafe {
            std::env::set_var("CLAUDE_CODE_SESSION_ID", "not-a-uuid");
        }
        assert!(!is_under_scratch(&format!(
            "{root}/-home-u-proj/not-a-uuid/scratchpad/f"
        )));

        unsafe {
            match saved_scratch {
                Some(v) => std::env::set_var("TOOL_GATES_SCRATCH", v),
                None => std::env::remove_var("TOOL_GATES_SCRATCH"),
            }
            match saved_sid {
                Some(v) => std::env::set_var("CLAUDE_CODE_SESSION_ID", v),
                None => std::env::remove_var("CLAUDE_CODE_SESSION_ID"),
            }
        }
    }

    #[serial_test::serial]
    #[test]
    fn test_redirect_into_claude_scratchpad_skips_soft_ask() {
        let sid = "01234567-89ab-cdef-0123-456789abcdef";
        let saved_scratch = std::env::var("TOOL_GATES_SCRATCH").ok();
        let saved_sid = std::env::var("CLAUDE_CODE_SESSION_ID").ok();
        // SAFETY: serialized via #[serial], so no concurrent env access.
        unsafe {
            std::env::set_var("TOOL_GATES_SCRATCH", "/tmp/cc-scratch-test");
            std::env::set_var("CLAUDE_CODE_SESSION_ID", sid);
        }

        let root = claude_scratchpad_root().to_string_lossy().into_owned();
        let pad = format!("{root}/-home-u-proj/{sid}/scratchpad");

        // Redirect into the session scratchpad: soft-ask suppressed, echo is
        // safe -> allow.
        let into = check_command_with_settings(
            &format!("echo hi > {pad}/out.log"),
            "/home/user/project",
            "default",
        );
        assert_eq!(
            get_decision(&into),
            "allow",
            "redirect into claude scratchpad should allow, got: {}",
            get_reason(&into)
        );

        // The tasks/ sibling is outside the scratchpad scope -> still asks.
        let sibling = check_command_with_settings(
            &format!("echo hi > {root}/-home-u-proj/{sid}/tasks/t.output"),
            "/home/user/project",
            "default",
        );
        assert_eq!(
            get_decision(&sibling),
            "ask",
            "redirect into the tasks/ sibling should ask"
        );

        unsafe {
            match saved_scratch {
                Some(v) => std::env::set_var("TOOL_GATES_SCRATCH", v),
                None => std::env::remove_var("TOOL_GATES_SCRATCH"),
            }
            match saved_sid {
                Some(v) => std::env::set_var("CLAUDE_CODE_SESSION_ID", v),
                None => std::env::remove_var("CLAUDE_CODE_SESSION_ID"),
            }
        }
    }

    #[test]
    fn test_path_has_unresolved_expansion() {
        // Unresolved expansions of every shape -> true (must fail closed).
        assert!(path_has_unresolved_expansion("/base/$X/y"));
        assert!(path_has_unresolved_expansion("/base/${X}/y"));
        assert!(path_has_unresolved_expansion("/base/${X:-../../etc}/y"));
        assert!(path_has_unresolved_expansion("/base/$(echo ../../etc)/y"));
        assert!(path_has_unresolved_expansion("/base/$1/y"));
        assert!(path_has_unresolved_expansion("/base/$@/y"));
        assert!(path_has_unresolved_expansion("/base/`echo x`/y"));
        // a$b would have $b expanded by the shell, so it must fail closed too.
        assert!(path_has_unresolved_expansion("/base/a$b/y"));

        // Fully-resolved paths and a literal `$` not starting an expansion
        // (followed by `/` or end) are not flagged.
        assert!(!path_has_unresolved_expansion("/base/sub/f.txt"));
        assert!(!path_has_unresolved_expansion("/tmp/cc-scratch/p/s/f"));
        assert!(!path_has_unresolved_expansion("/base/cost$/f"));
        assert!(!path_has_unresolved_expansion("/base/end$"));
    }

    #[test]
    fn test_resolve_scratch_convention_tokens() {
        let sid = Some("sess-123");
        let pwd = Some("/home/u/proj");

        // Session id in bare, braced, and default forms all resolve.
        assert_eq!(
            resolve_scratch_convention_tokens("/b/$CLAUDE_CODE_SESSION_ID/f", sid, pwd),
            "/b/sess-123/f"
        );
        assert_eq!(
            resolve_scratch_convention_tokens("/b/${CLAUDE_CODE_SESSION_ID}/f", sid, pwd),
            "/b/sess-123/f"
        );
        assert_eq!(
            resolve_scratch_convention_tokens("/b/${CLAUDE_CODE_SESSION_ID:-fallback}/f", sid, pwd),
            "/b/sess-123/f"
        );

        // PWD slash-replacement slug (the `\/` escaped form the convention uses).
        assert_eq!(
            resolve_scratch_convention_tokens("/b/${PWD//\\//-}/f", sid, pwd),
            "/b/home-u-proj/f"
        );

        // With no session id: only `:-default` is resolvable; bare/braced stay
        // intact so the residual guard rejects them.
        assert_eq!(
            resolve_scratch_convention_tokens("/b/${CLAUDE_CODE_SESSION_ID:-sess}/f", None, pwd),
            "/b/sess/f"
        );
        assert_eq!(
            resolve_scratch_convention_tokens("/b/$CLAUDE_CODE_SESSION_ID/f", None, pwd),
            "/b/$CLAUDE_CODE_SESSION_ID/f"
        );

        // A longer name is not partially consumed by the bare form, and
        // unrelated variables are left untouched.
        assert_eq!(
            resolve_scratch_convention_tokens("/b/$CLAUDE_CODE_SESSION_IDX/f", sid, pwd),
            "/b/$CLAUDE_CODE_SESSION_IDX/f"
        );
        assert_eq!(
            resolve_scratch_convention_tokens("/b/$OTHER/f", sid, pwd),
            "/b/$OTHER/f"
        );

        // No pwd known -> a safe slash-free placeholder, still no residual `$`.
        let resolved = resolve_scratch_convention_tokens("/b/${PWD//\\//-}/f", sid, None);
        assert!(!resolved.contains("${PWD"));
        assert!(!path_has_unresolved_expansion(&resolved));
    }

    #[serial_test::serial]
    #[test]
    fn test_scratch_fail_closed_on_unresolved_expansion() {
        let saved_scratch = std::env::var("TOOL_GATES_SCRATCH").ok();
        let saved_sid = std::env::var("CLAUDE_CODE_SESSION_ID").ok();
        let saved_pwd = std::env::var("PWD").ok();
        // SAFETY: serialized via #[serial], so no concurrent env access.
        unsafe {
            std::env::set_var("TOOL_GATES_SCRATCH", "/tmp/cc-scratch-test");
            std::env::set_var("CLAUDE_CODE_SESSION_ID", "sess-xyz");
            std::env::set_var("PWD", "/home/u/proj");
        }

        // The canonical scratchpad convention path stays friction-free.
        assert!(is_under_scratch(
            "$TOOL_GATES_SCRATCH/${PWD//\\//-}/$CLAUDE_CODE_SESSION_ID/f.txt"
        ));
        assert!(is_under_scratch(
            "$TOOL_GATES_SCRATCH/${CLAUDE_CODE_SESSION_ID:-sess}/f.txt"
        ));

        // The residual-hole classes now fail closed (not under scratch -> the
        // write falls through to a prompt instead of silently auto-allowing).
        assert!(!is_under_scratch("$TOOL_GATES_SCRATCH/$UNDEF/y")); // undefined / env / command-prefix var
        assert!(!is_under_scratch("$TOOL_GATES_SCRATCH/${UNDEF}/y"));
        assert!(!is_under_scratch("$TOOL_GATES_SCRATCH/${X:-../../etc}/y")); // operator-default with traversal
        assert!(!is_under_scratch("$TOOL_GATES_SCRATCH/$(echo ../../etc)/y")); // use-site command substitution

        // A fully-literal in-scratch path is unaffected.
        assert!(is_under_scratch("$TOOL_GATES_SCRATCH/plain/f.txt"));

        // SAFETY: serialized via #[serial].
        unsafe {
            match saved_scratch {
                Some(v) => std::env::set_var("TOOL_GATES_SCRATCH", v),
                None => std::env::remove_var("TOOL_GATES_SCRATCH"),
            }
            match saved_sid {
                Some(v) => std::env::set_var("CLAUDE_CODE_SESSION_ID", v),
                None => std::env::remove_var("CLAUDE_CODE_SESSION_ID"),
            }
            match saved_pwd {
                Some(v) => std::env::set_var("PWD", v),
                None => std::env::remove_var("PWD"),
            }
        }
    }

    #[serial_test::serial]
    #[test]
    fn test_scratch_cmdsub_valued_var_fails_closed() {
        let saved_scratch = std::env::var("TOOL_GATES_SCRATCH").ok();
        // SAFETY: serialized via #[serial], so no concurrent env access.
        unsafe {
            std::env::set_var("TOOL_GATES_SCRATCH", "/tmp/cc-scratch-test");
        }

        // Y is assigned from a command substitution, so it is not tracked
        // (value_is_static rejects cmdsub). The self-contained one-liner that
        // previously defeated the variable-tracking guard now fails closed: the
        // use-site `$Y` is an unresolved expansion.
        let cmd = "Y=$(echo ../../etc); mkdir \"$TOOL_GATES_SCRATCH/$Y/y\"";
        let vars = crate::parser::extract_scratch_var_map(cmd);
        assert!(
            !vars.contains_key("Y"),
            "cmdsub-valued var must not be tracked"
        );
        assert!(!is_under_scratch_with_vars(
            "$TOOL_GATES_SCRATCH/$Y/y",
            &vars
        ));

        // A tracked, static, in-scratch value still resolves to allow.
        let cmd2 = "S=$TOOL_GATES_SCRATCH/run; mkdir \"$S/y\"";
        let vars2 = crate::parser::extract_scratch_var_map(cmd2);
        assert!(is_under_scratch_with_vars("$S/y", &vars2));

        // SAFETY: serialized via #[serial].
        unsafe {
            match saved_scratch {
                Some(v) => std::env::set_var("TOOL_GATES_SCRATCH", v),
                None => std::env::remove_var("TOOL_GATES_SCRATCH"),
            }
        }
    }

    /// fd-prefixed (`1>`, `2>`, `9>`) and `>&FILE` write redirects to a
    /// non-scratch file must prompt. Regression guard for the bypass where
    /// `REDIRECT_RE`'s `[^0-9...]` boundary hid every fd-numbered redirect and
    /// its `[^>&]` target class hid the `>&FILE` form, so writes to arbitrary
    /// paths (e.g. `printf x 1> /etc/passwd`) were auto-allowed with no prompt.
    #[test]
    fn test_fd_numbered_and_amp_redirects_ask() {
        for cmd in [
            "echo x 1> /etc/evil.txt",
            "echo x 2> /etc/evil.txt",
            "echo x 3> /etc/evil.txt",
            "echo x 9> /etc/evil.txt",
            "printf data 1> /etc/passwd",
            "echo x 1>> /etc/evil.txt",
            "echo x >& /etc/evil.txt",
            "echo x 1>& /etc/evil.txt",
            "echo x >>& /etc/evil.txt",
            "echo x >&/etc/evil.txt",
        ] {
            assert_eq!(
                get_decision(&check_command(cmd)),
                "ask",
                "fd/amp redirect to a non-scratch file must prompt: {cmd}"
            );
        }
    }

    /// fd duplications (`2>&1`, `>&2`, `2>&-`) move a descriptor; they are not
    /// file writes and must not be flagged as redirections, so a safe command
    /// keeps its allow.
    #[test]
    fn test_fd_duplications_not_flagged_as_writes() {
        for cmd in [
            "echo hello 2>&1",
            "echo hello >&2",
            "echo x 2>&-",
            "echo hello 1>&2",
        ] {
            assert_eq!(
                get_decision(&check_command(cmd)),
                "allow",
                "fd duplication must not be flagged as a file write: {cmd}"
            );
        }
    }

    /// `/dev/null` (including fd-prefixed) discards output and is exempt; bare
    /// `>` and `&>` to a non-scratch file still prompt.
    #[test]
    fn test_redirect_devnull_and_controls_unchanged() {
        assert_eq!(get_decision(&check_command("echo x > /dev/null")), "allow");
        assert_eq!(get_decision(&check_command("echo x 2> /dev/null")), "allow");
        assert_eq!(
            get_decision(&check_command("echo x > /etc/evil.txt")),
            "ask"
        );
        assert_eq!(
            get_decision(&check_command("echo x &> /etc/evil.txt")),
            "ask"
        );
    }

    /// fd-prefixed and `>&` redirects into the scratch base are friction-free,
    /// same as a bare `>` into scratch.
    #[serial_test::serial]
    #[test]
    fn test_fd_redirect_into_scratch_allows() {
        let saved = std::env::var("TOOL_GATES_SCRATCH").ok();
        // SAFETY: serialized via #[serial], so no concurrent env access.
        unsafe {
            std::env::set_var("TOOL_GATES_SCRATCH", "/tmp/cc-scratch-test");
        }

        assert_eq!(
            get_decision(&check_command("echo x 1> /tmp/cc-scratch-test/f")),
            "allow"
        );
        assert_eq!(
            get_decision(&check_command("echo x >& /tmp/cc-scratch-test/f")),
            "allow"
        );
        assert_eq!(
            get_decision(&check_command("echo x > /tmp/cc-scratch-test/f")),
            "allow"
        );

        unsafe {
            match saved {
                Some(v) => std::env::set_var("TOOL_GATES_SCRATCH", v),
                None => std::env::remove_var("TOOL_GATES_SCRATCH"),
            }
        }
    }

    /// An over-broad `TOOL_GATES_SCRATCH` (`/`, a bare top-level dir, or the
    /// home dir) must fail closed: `scratch_base` returns `None` so the scratch
    /// exemption cannot match credentials / system paths via prefix.
    #[serial_test::serial]
    #[test]
    fn test_scratch_base_rejects_overbroad() {
        let saved = std::env::var("TOOL_GATES_SCRATCH").ok();
        // SAFETY: serialized via #[serial], so no concurrent env access.
        let set = |v: &str| unsafe { std::env::set_var("TOOL_GATES_SCRATCH", v) };

        set("/");
        assert_eq!(scratch_base(), None, "/ must be rejected");
        assert!(!is_under_scratch("/etc/passwd"));
        assert!(!is_under_scratch("/home/u/.ssh/authorized_keys"));

        set("/home");
        assert_eq!(scratch_base(), None, "/home must be rejected");
        set("/etc");
        assert_eq!(scratch_base(), None, "/etc must be rejected");

        if let Some(home) = dirs::home_dir() {
            set(&home.to_string_lossy());
            assert_eq!(scratch_base(), None, "home dir itself must be rejected");
        }

        // A nested, specific base is accepted.
        set("/tmp/cc-scratch-test");
        assert_eq!(scratch_base().as_deref(), Some("/tmp/cc-scratch-test"));
        assert!(is_under_scratch("/tmp/cc-scratch-test/f"));

        unsafe {
            match saved {
                Some(v) => std::env::set_var("TOOL_GATES_SCRATCH", v),
                None => std::env::remove_var("TOOL_GATES_SCRATCH"),
            }
        }
    }

    /// A symlink inside the scratch base pointing outside, followed by two or
    /// more not-yet-existing segments (the `mkdir -p` shape), must not resolve
    /// as scratch: `resolve_path` canonicalizes the longest existing ancestor,
    /// resolving the symlink, so the real (outside) target is seen.
    #[cfg(unix)]
    #[serial_test::serial]
    #[test]
    fn test_deep_symlink_does_not_escape_scratch() {
        let saved = std::env::var("TOOL_GATES_SCRATCH").ok();

        let base = std::env::temp_dir().join("tg-symlink-escape-base");
        let outside = std::env::temp_dir().join("tg-symlink-escape-outside");
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, base.join("link")).unwrap();

        // SAFETY: serialized via #[serial], so no concurrent env access.
        unsafe {
            std::env::set_var("TOOL_GATES_SCRATCH", base.to_string_lossy().as_ref());
        }
        let base_s = base.to_string_lossy().into_owned();

        assert!(
            !is_under_scratch(&format!("{base_s}/link/a/b")),
            "symlink + 2 missing segments must not resolve as scratch"
        );
        assert!(
            !is_under_scratch(&format!("{base_s}/link/a/b/c/d")),
            "symlink + deep missing segments must not resolve as scratch"
        );
        // A real (non-symlinked) path under the base is still scratch.
        assert!(is_under_scratch(&format!("{base_s}/real/x")));

        unsafe {
            match saved {
                Some(v) => std::env::set_var("TOOL_GATES_SCRATCH", v),
                None => std::env::remove_var("TOOL_GATES_SCRATCH"),
            }
        }
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// Variable-tracking: a write through a single, unconditional, top-level,
    /// static shell variable resolves like the inline path and auto-allows.
    /// The opaque shapes (reassignment, command-prefix, conditional `&&`,
    /// append, `export`-wrapped, command-substitution value) and a `..` escape
    /// must never auto-allow.
    #[serial_test::serial]
    #[test]
    fn test_scratch_variable_tracking() {
        let saved = std::env::var("TOOL_GATES_SCRATCH").ok();
        // SAFETY: serialized via #[serial], so no concurrent env access.
        unsafe {
            std::env::set_var("TOOL_GATES_SCRATCH", "/tmp/cc-scratch-test");
        }

        for cmd in [
            "S=\"$TOOL_GATES_SCRATCH/x\"; mkdir -p \"$S\"",
            "o=\"$TOOL_GATES_SCRATCH/x\"; echo hi > \"$o/f\"",
            "D=\"$TOOL_GATES_SCRATCH/x\"; cp /etc/hostname \"$D/h\"",
            "A=\"$TOOL_GATES_SCRATCH\"; B=\"$A/x\"; mkdir -p \"$B\"",
        ] {
            assert_eq!(
                get_decision(&check_command(cmd)),
                "allow",
                "indirect scratch write should auto-allow: {cmd}"
            );
        }

        for cmd in [
            "S=/etc; mkdir -p \"$S/x\"",
            "S=\"$TOOL_GATES_SCRATCH/x\"; mkdir \"$S/../../etc\"",
            "S=\"$(pwd)\"; mkdir -p \"$S/x\"",
            "S=\"$TOOL_GATES_SCRATCH/a\"; S=/etc; mkdir \"$S/v\"",
            "S=\"$TOOL_GATES_SCRATCH/a\" mkdir \"$S/x\"",
            "cd / && S=\"$TOOL_GATES_SCRATCH/x\" && mkdir \"$S\"",
            "S=\"$TOOL_GATES_SCRATCH\"; S+=/x; mkdir \"$S\"",
            "export S=\"$TOOL_GATES_SCRATCH/x\"; mkdir \"$S\"",
        ] {
            assert_ne!(
                get_decision(&check_command(cmd)),
                "allow",
                "opaque/escape variable shape must not auto-allow: {cmd}"
            );
        }

        unsafe {
            match saved {
                Some(v) => std::env::set_var("TOOL_GATES_SCRATCH", v),
                None => std::env::remove_var("TOOL_GATES_SCRATCH"),
            }
        }
    }

    #[serial_test::serial]
    #[test]
    fn test_redirect_into_scratch_skips_soft_ask() {
        let saved = std::env::var("TOOL_GATES_SCRATCH").ok();
        // SAFETY: serialized via #[serial], so no concurrent env access.
        unsafe {
            std::env::set_var("TOOL_GATES_SCRATCH", "/tmp/cc-scratch-test");
        }

        // Redirect into scratch: soft-ask suppressed, echo is safe -> allow.
        let into = check_command_with_settings(
            "echo hi > /tmp/cc-scratch-test/out.log",
            "/home/user/project",
            "default",
        );
        assert_eq!(
            get_decision(&into),
            "allow",
            "redirect into scratch should allow, got: {}",
            get_reason(&into)
        );

        // Redirect elsewhere still asks.
        let elsewhere = check_command_with_settings(
            "echo hi > /tmp/other/out.log",
            "/home/user/project",
            "default",
        );
        assert_eq!(
            get_decision(&elsewhere),
            "ask",
            "redirect outside scratch should ask"
        );

        // QUOTED redirect targets under scratch must also allow. strip_quoted_strings
        // blanks the quoted path to `_`, so the real target is recovered from the
        // original command before the scratch check. Covers the `>`, `>>`, and `&>`
        // forms and the literal-token + absolute spellings.
        for q in [
            "echo hi > \"$TOOL_GATES_SCRATCH/out.log\"",
            "echo hi >> \"$TOOL_GATES_SCRATCH/sess/out.log\"",
            "echo hi > \"/tmp/cc-scratch-test/abs.log\"",
            "echo hi &> \"$TOOL_GATES_SCRATCH/both.log\"",
        ] {
            let r = check_command_with_settings(q, "/home/user/project", "default");
            assert_eq!(
                get_decision(&r),
                "allow",
                "quoted scratch redirect should allow: {q} -> {}",
                get_reason(&r)
            );
        }

        // A QUOTED non-scratch target still asks (the fix must not over-allow).
        let quoted_other = check_command_with_settings(
            "echo hi > \"/tmp/other/out.log\"",
            "/home/user/project",
            "default",
        );
        assert_eq!(
            get_decision(&quoted_other),
            "ask",
            "quoted non-scratch redirect should still ask"
        );

        unsafe {
            match saved {
                Some(v) => std::env::set_var("TOOL_GATES_SCRATCH", v),
                None => std::env::remove_var("TOOL_GATES_SCRATCH"),
            }
        }
    }

    // === WASM simulator instrumentation ===
    //
    // These run natively (they call the inner `decide_instrumented`, not the
    // `#[wasm_bindgen]` shim) but are gated on the `wasm` feature so the data
    // structures they exercise are only compiled in that build. Run with
    // `cargo test --features wasm`.
}

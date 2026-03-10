//! Centralized cache directory management with migration from bash-gates.

use std::path::PathBuf;

/// Get the tool-gates cache directory path.
///
/// Uses `XDG_CACHE_HOME` if set, otherwise `~/.cache`, with `tool-gates/` appended.
pub fn cache_dir() -> PathBuf {
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .ok()
        .or_else(|| dirs::home_dir().map(|h| h.join(".cache")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("tool-gates")
}

/// One-time migration from `~/.cache/bash-gates/` to `~/.cache/tool-gates/`.
///
/// Called once at startup. If old dir exists and new doesn't, moves it.
/// Fire-and-forget: if the rename fails, fresh files are created at the new path.
pub fn ensure_cache_migrated() {
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .ok()
        .or_else(|| dirs::home_dir().map(|h| h.join(".cache")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));

    let old = base.join("bash-gates");
    let new = base.join("tool-gates");

    if old.exists() && !new.exists() {
        let _ = std::fs::rename(&old, &new);
    }
}

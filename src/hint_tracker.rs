//! Session-scoped dedup tracker for hints and security warnings.
//!
//! Tracks which hints and warnings have been emitted during the current
//! session. Each entry fires at most once per session, reducing the
//! context tax from repeated `<system-reminder>` injections.
//!
//! File: `~/.cache/tool-gates/hint-tracker.json`

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// Global tracker. Loaded once per process, mutated in-place.
static TRACKER: OnceLock<Mutex<HintTracker>> = OnceLock::new();

/// Session-scoped dedup state.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HintTracker {
    /// Current session ID (resets tracker when session changes)
    pub session_id: String,
    /// Hint keys already emitted (e.g. "cat", "grep", "find")
    #[serde(default)]
    pub hints: HashSet<String>,
    /// Security warning keys already shown (e.g. "/tmp/f.js-eval_injection")
    #[serde(default)]
    pub security_warnings: HashSet<String>,
    /// Whether state has changed since load (skip disk write if clean)
    #[serde(skip)]
    dirty: bool,
}

impl HintTracker {
    /// Load tracker from disk, resetting if session_id doesn't match.
    fn load(session_id: &str) -> Self {
        if let Some(tracker) = load_from_disk() {
            if tracker.session_id == session_id {
                return tracker;
            }
        }
        HintTracker {
            session_id: session_id.to_string(),
            ..Default::default()
        }
    }

    /// Check if a hint key is new for this session. Records it if so.
    pub fn is_hint_new(&mut self, hint_key: &str) -> bool {
        if self.hints.contains(hint_key) {
            return false;
        }
        self.hints.insert(hint_key.to_string());
        self.dirty = true;
        true
    }

    /// Check if a security warning key is new for this session.
    pub fn is_security_warning_new(&mut self, key: &str) -> bool {
        if self.security_warnings.contains(key) {
            return false;
        }
        self.security_warnings.insert(key.to_string());
        self.dirty = true;
        true
    }

    /// Save to disk if state changed since load.
    pub fn save_if_dirty(&self) {
        if !self.dirty {
            return;
        }
        let _ = save_to_disk(self);
    }
}

fn tracker_path() -> Option<PathBuf> {
    Some(crate::cache::cache_dir().join("hint-tracker.json"))
}

fn load_from_disk() -> Option<HintTracker> {
    let path = tracker_path()?;
    let content = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

fn save_to_disk(tracker: &HintTracker) -> Result<(), std::io::Error> {
    let path = tracker_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not determine cache path",
        )
    })?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string(tracker)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &content)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Get the global tracker. Initializes on first call.
pub fn get(session_id: &str) -> std::sync::MutexGuard<'static, HintTracker> {
    let mutex = TRACKER.get_or_init(|| Mutex::new(HintTracker::load(session_id)));
    mutex.lock().unwrap()
}

/// Filter hints, retaining only those not yet shown this session.
/// Empty `session_id` skips filtering (backward compat).
pub fn filter_hints(session_id: &str, hints: &mut Vec<crate::hints::ModernHint>) {
    if session_id.is_empty() || hints.is_empty() {
        return;
    }
    let mut tracker = get(session_id);
    hints.retain(|h| tracker.is_hint_new(h.legacy_command));
    tracker.save_if_dirty();
}

/// Check if a security warning is new for this session. Persists to disk.
pub fn is_security_warning_new(session_id: &str, key: &str) -> bool {
    if session_id.is_empty() {
        return true;
    }
    let mut tracker = get(session_id);
    let is_new = tracker.is_security_warning_new(key);
    tracker.save_if_dirty();
    is_new
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(session_id: &str) -> HintTracker {
        HintTracker {
            session_id: session_id.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_hint_first_time_is_new() {
        let mut t = fresh("s1");
        assert!(t.is_hint_new("cat"));
        assert!(t.is_hint_new("grep"));
    }

    #[test]
    fn test_hint_second_time_suppressed() {
        let mut t = fresh("s1");
        assert!(t.is_hint_new("cat"));
        assert!(!t.is_hint_new("cat"));
    }

    #[test]
    fn test_warning_first_time_is_new() {
        let mut t = fresh("s1");
        assert!(t.is_security_warning_new("/tmp/f.js-eval_injection"));
    }

    #[test]
    fn test_warning_second_time_suppressed() {
        let mut t = fresh("s1");
        assert!(t.is_security_warning_new("key"));
        assert!(!t.is_security_warning_new("key"));
    }

    #[test]
    fn test_dirty_on_new_entry() {
        let mut t = fresh("s1");
        assert!(!t.dirty);
        t.is_hint_new("cat");
        assert!(t.dirty);
    }

    #[test]
    fn test_not_dirty_on_duplicate() {
        let mut t = fresh("s1");
        t.is_hint_new("cat");
        t.dirty = false;
        t.is_hint_new("cat");
        assert!(!t.dirty);
    }

    #[test]
    fn test_session_change_resets() {
        let mut t = fresh("s1");
        t.is_hint_new("cat");
        assert!(!t.is_hint_new("cat"));

        let mut t2 = fresh("s2");
        assert!(t2.is_hint_new("cat"));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut t = fresh("s1");
        t.is_hint_new("cat");
        t.is_security_warning_new("k1");

        let json = serde_json::to_string(&t).unwrap();
        let loaded: HintTracker = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.session_id, "s1");
        assert!(loaded.hints.contains("cat"));
        assert!(loaded.security_warnings.contains("k1"));
    }

    #[test]
    fn test_filter_hints_empty_session_passes_through() {
        use crate::hints::ModernHint;
        let mut hints = vec![ModernHint {
            legacy_command: "cat",
            modern_command: "bat",
            hint: "Use bat".to_string(),
        }];
        filter_hints("", &mut hints);
        assert_eq!(hints.len(), 1);
    }

    #[test]
    fn test_security_warning_empty_session_always_new() {
        assert!(is_security_warning_new("", "key"));
        assert!(is_security_warning_new("", "key"));
    }
}

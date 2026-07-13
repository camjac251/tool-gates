//! Multi-session dedup tracker for hints and security warnings.
//!
//! File: `~/.cache/tool-gates/hint-tracker.json`

use chrono::{DateTime, Duration, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::Builder;

const SCHEMA_VERSION: u8 = 2;
const SESSION_TTL_SECS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SessionState {
    #[serde(default)]
    hints: HashSet<String>,
    #[serde(default)]
    security_warnings: HashSet<String>,
    updated_at: DateTime<Utc>,
}

impl SessionState {
    fn new() -> Self {
        Self {
            hints: HashSet::new(),
            security_warnings: HashSet::new(),
            updated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HintStore {
    version: u8,
    #[serde(default)]
    sessions: HashMap<String, SessionState>,
}

impl Default for HintStore {
    fn default() -> Self {
        Self {
            version: SCHEMA_VERSION,
            sessions: HashMap::new(),
        }
    }
}

impl HintStore {
    fn clean_expired_at(&mut self, now: DateTime<Utc>) {
        let cutoff = now - Duration::seconds(SESSION_TTL_SECS);
        self.sessions
            .retain(|_, session| session.updated_at >= cutoff);
    }

    fn session_mut(&mut self, session_id: &str) -> &mut SessionState {
        self.sessions
            .entry(session_id.to_string())
            .or_insert_with(SessionState::new)
    }
}

#[derive(Debug, Default, Deserialize)]
struct LegacyTracker {
    session_id: String,
    #[serde(default)]
    hints: HashSet<String>,
    #[serde(default)]
    security_warnings: HashSet<String>,
}

fn tracker_path() -> PathBuf {
    crate::cache::cache_dir().join("hint-tracker.json")
}

fn lock_path(path: &Path) -> PathBuf {
    path.with_file_name("hint-tracker.json.lock")
}

fn parse_store(content: &str) -> (HintStore, bool) {
    if content.trim().is_empty() {
        return (HintStore::default(), false);
    }

    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return (HintStore::default(), true);
    };
    if value.get("sessions").is_some() {
        let Ok(mut store) = serde_json::from_value::<HintStore>(value) else {
            return (HintStore::default(), true);
        };
        let needs_rewrite = store.version != SCHEMA_VERSION;
        store.version = SCHEMA_VERSION;
        return (store, needs_rewrite);
    }

    let legacy = serde_json::from_value::<LegacyTracker>(value).unwrap_or_default();
    let mut store = HintStore::default();
    if !legacy.session_id.is_empty() {
        store.sessions.insert(
            legacy.session_id,
            SessionState {
                hints: legacy.hints,
                security_warnings: legacy.security_warnings,
                updated_at: Utc::now(),
            },
        );
    }
    (store, true)
}

fn with_locked_store_at<R>(path: &Path, mutate: impl FnOnce(&mut HintStore) -> R) -> io::Result<R> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path(path))?;
    #[allow(clippy::incompatible_msrv)]
    lock.lock_exclusive()?;

    let mut content = String::new();
    match File::open(path) {
        Ok(mut file) => {
            file.read_to_string(&mut content)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let (mut store, mut needs_rewrite) = parse_store(&content);
    let session_count = store.sessions.len();
    store.clean_expired_at(Utc::now());
    needs_rewrite |= store.sessions.len() != session_count;
    let before = store.clone();
    let result = mutate(&mut store);

    if needs_rewrite || store != before {
        persist_store(path, parent, &store)?;
    }

    FileExt::unlock(&lock)?;
    Ok(result)
}

fn persist_store(path: &Path, parent: &Path, store: &HintStore) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(store).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let mut temp = Builder::new()
        .prefix(".hint-tracker-")
        .tempfile_in(parent)?;
    temp.write_all(&bytes)?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;
    sync_parent(parent)
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> io::Result<()> {
    Ok(())
}

fn record_hint_keys_at(
    path: &Path,
    session_id: &str,
    keys: &[&str],
) -> io::Result<HashSet<String>> {
    with_locked_store_at(path, |store| {
        let session = store.session_mut(session_id);
        let mut new = HashSet::new();
        for key in keys {
            if session.hints.insert((*key).to_string()) {
                new.insert((*key).to_string());
            }
        }
        if !new.is_empty() {
            session.updated_at = Utc::now();
        }
        new
    })
}

fn record_hint_keys(session_id: &str, keys: &[&str]) -> io::Result<HashSet<String>> {
    record_hint_keys_at(&tracker_path(), session_id, keys)
}

fn record_security_warning_at(path: &Path, session_id: &str, key: &str) -> io::Result<bool> {
    with_locked_store_at(path, |store| {
        let session = store.session_mut(session_id);
        let is_new = session.security_warnings.insert(key.to_string());
        if is_new {
            session.updated_at = Utc::now();
        }
        is_new
    })
}

fn record_security_warning(session_id: &str, key: &str) -> io::Result<bool> {
    record_security_warning_at(&tracker_path(), session_id, key)
}

/// Filter hints, retaining only those not yet shown in this session.
/// Empty `session_id` skips filtering for backward compatibility. Disk errors
/// fail open so a persistence problem never hides useful context.
pub fn filter_hints(session_id: &str, hints: &mut Vec<crate::hints::ModernHint>) {
    if session_id.is_empty() || hints.is_empty() {
        return;
    }
    let keys = hints
        .iter()
        .map(|hint| hint.legacy_command)
        .collect::<Vec<_>>();
    if let Ok(new) = record_hint_keys(session_id, &keys) {
        hints.retain(|hint| new.contains(hint.legacy_command));
    }
}

/// Check whether a security warning is new for this session.
/// Persistence errors fail open so warnings remain visible.
pub fn is_security_warning_new(session_id: &str, key: &str) -> bool {
    if session_id.is_empty() {
        return true;
    }
    record_security_warning(session_id, key).unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hints::ModernHint;

    fn isolated_tracker() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("cache tempdir");
        let path = temp.path().join("hint-tracker.json");
        (temp, path)
    }

    fn hint(key: &'static str) -> ModernHint {
        ModernHint {
            legacy_command: key,
            modern_command: "mytool",
            hint: "Use mytool".to_string(),
        }
    }

    #[test]
    fn store_keeps_sessions_independent_and_prunes_expired_state() {
        let mut store = HintStore::default();
        store.session_mut("session-a").hints.insert("first".into());
        store.session_mut("session-b").hints.insert("second".into());
        store.sessions.get_mut("session-a").unwrap().updated_at =
            Utc::now() - Duration::seconds(SESSION_TTL_SECS + 1);

        store.clean_expired_at(Utc::now());
        assert!(!store.sessions.contains_key("session-a"));
        assert!(store.sessions["session-b"].hints.contains("second"));
    }

    #[test]
    fn legacy_file_migrates_into_the_session_map() {
        let (store, needs_rewrite) = parse_store(
            r#"{"session_id":"session-old","hints":["first"],"security_warnings":["warning"]}"#,
        );
        assert!(needs_rewrite);
        assert_eq!(store.version, SCHEMA_VERSION);
        assert!(store.sessions["session-old"].hints.contains("first"));
        assert!(
            store.sessions["session-old"]
                .security_warnings
                .contains("warning")
        );
    }

    #[test]
    fn legacy_file_is_rewritten_when_the_recorded_hint_is_a_duplicate() {
        let (_cache, path) = isolated_tracker();
        fs::write(
            &path,
            r#"{"session_id":"session-old","hints":["first"],"security_warnings":[]}"#,
        )
        .expect("seed legacy tracker");

        let new =
            record_hint_keys_at(&path, "session-old", &["first"]).expect("record duplicate hint");
        assert!(new.is_empty());

        let content = fs::read_to_string(path).expect("read migrated tracker");
        let value: serde_json::Value = serde_json::from_str(&content).expect("parse tracker");
        assert_eq!(value["version"], SCHEMA_VERSION);
        assert!(value.get("sessions").is_some());
        assert!(value.get("session_id").is_none());
    }

    #[test]
    fn expired_sessions_are_removed_when_the_current_record_is_a_duplicate() {
        let (_cache, path) = isolated_tracker();
        let mut store = HintStore::default();
        store
            .session_mut("current-session")
            .security_warnings
            .insert("warning".into());
        store.session_mut("expired-session").updated_at =
            Utc::now() - Duration::seconds(SESSION_TTL_SECS + 1);
        persist_store(&path, path.parent().unwrap(), &store).expect("seed tracker");

        assert!(
            !record_security_warning_at(&path, "current-session", "warning")
                .expect("record warning")
        );

        let content = fs::read_to_string(path).expect("read cleaned tracker");
        let (store, _) = parse_store(&content);
        assert!(store.sessions.contains_key("current-session"));
        assert!(!store.sessions.contains_key("expired-session"));
    }

    #[test]
    fn alternating_sessions_do_not_reset_each_other() {
        let (_cache, path) = isolated_tracker();

        let first =
            record_hint_keys_at(&path, "session-a", &["first"]).expect("record first session");
        assert!(first.contains("first"));

        let second =
            record_hint_keys_at(&path, "session-b", &["first"]).expect("record second session");
        assert!(second.contains("first"));

        let repeated =
            record_hint_keys_at(&path, "session-a", &["first"]).expect("record repeated hint");
        assert!(repeated.is_empty());

        let content = fs::read_to_string(path).expect("read tracker");
        let (store, _) = parse_store(&content);
        assert_eq!(store.sessions.len(), 2);
    }

    #[test]
    fn concurrent_process_style_updates_do_not_lose_sessions() {
        let (_cache, path) = isolated_tracker();
        let threads = (0..16)
            .map(|index| {
                let path = path.clone();
                std::thread::spawn(move || {
                    record_security_warning_at(
                        &path,
                        &format!("session-{index}"),
                        &format!("warning-{index}"),
                    )
                    .expect("record warning");
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().expect("join warning thread");
        }

        let content = fs::read_to_string(path).expect("read tracker");
        let (store, _) = parse_store(&content);
        assert_eq!(store.sessions.len(), 16);
        for index in 0..16 {
            assert!(
                store.sessions[&format!("session-{index}")]
                    .security_warnings
                    .contains(&format!("warning-{index}"))
            );
        }
    }

    #[test]
    fn empty_session_bypasses_dedup() {
        let mut hints = vec![hint("first")];
        filter_hints("", &mut hints);
        assert_eq!(hints.len(), 1);
        assert!(is_security_warning_new("", "warning"));
        assert!(is_security_warning_new("", "warning"));
    }
}

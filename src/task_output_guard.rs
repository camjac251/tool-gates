//! Session-scoped correlation for redundant blocking TaskOutput waits.

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::{HookInput, HookOutput, PostToolUseInput};

const ENTRY_TTL_SECS: u64 = 10 * 60;
const MAX_SESSIONS: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingBackground {
    task_id: String,
    bash_tool_use_id: String,
    recorded_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct GuardStore {
    entries: HashMap<String, PendingBackground>,
}

impl GuardStore {
    fn path() -> PathBuf {
        crate::cache::cache_dir().join("task-output-guard.json")
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }

    fn clean(&mut self, now: u64) {
        self.entries.retain(|_, entry| {
            now.saturating_sub(entry.recorded_at) <= ENTRY_TTL_SECS
                && !entry.task_id.is_empty()
                && !entry.bash_tool_use_id.is_empty()
        });
        if self.entries.len() > MAX_SESSIONS {
            let mut oldest = self
                .entries
                .iter()
                .map(|(session, entry)| (session.clone(), entry.recorded_at))
                .collect::<Vec<_>>();
            oldest.sort_by_key(|(_, recorded_at)| *recorded_at);
            for (session, _) in oldest.into_iter().take(self.entries.len() - MAX_SESSIONS) {
                self.entries.remove(&session);
            }
        }
    }

    fn with_exclusive_lock<F, R>(f: F) -> std::io::Result<R>
    where
        F: FnOnce(&mut Self) -> R,
    {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        #[allow(clippy::incompatible_msrv)]
        file.lock_exclusive()?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let mut store = if contents.is_empty() {
            Self::default()
        } else {
            serde_json::from_str(&contents).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid TaskOutput guard state: {error}"),
                )
            })?
        };
        store.clean(Self::now());
        let result = f(&mut store);

        let serialized = serde_json::to_string_pretty(&store)?;
        let unchanged_empty = contents.is_empty() && store.entries.is_empty();
        if !unchanged_empty && contents != serialized {
            file.set_len(0)?;
            file.seek(std::io::SeekFrom::Start(0))?;
            file.write_all(serialized.as_bytes())?;
            file.flush()?;
        }
        FileExt::unlock(&file)?;
        Ok(result)
    }
}

fn pending_background(post: &PostToolUseInput) -> Option<PendingBackground> {
    if post.tool_name != "Bash" || post.tool_use_id.is_empty() {
        return None;
    }
    let tool_input = post.tool_input.as_map()?;
    if tool_input
        .get("run_in_background")
        .and_then(|value| value.as_bool())
        != Some(true)
    {
        return None;
    }
    let task_id = post
        .tool_response
        .as_ref()
        .and_then(|response| response.get("backgroundTaskId"))
        .and_then(|value| value.as_str())
        .filter(|task_id| !task_id.is_empty())?;

    Some(PendingBackground {
        task_id: task_id.to_string(),
        bash_tool_use_id: post.tool_use_id.clone(),
        recorded_at: GuardStore::now(),
    })
}

/// Observe completed Claude work. Successful non-TaskOutput calls clear the
/// immediate sequence, while a qualifying background Bash result atomically
/// replaces it with the newly started task.
pub fn observe_post_tool_use(post: &PostToolUseInput) {
    if post.session_id.is_empty() || post.tool_name == "TaskOutput" || !post.is_success() {
        return;
    }
    let pending = pending_background(post);
    let session_id = post.session_id.clone();
    if let Err(error) = GuardStore::with_exclusive_lock(|store| {
        if let Some(pending) = pending {
            store.entries.insert(session_id, pending);
        } else {
            store.entries.remove(&session_id);
        }
        store.clean(GuardStore::now());
    }) {
        eprintln!("Warning: Failed to update background task state: {error}");
    }
}

/// Clear the pending candidate at a public user-turn boundary.
pub fn clear_session(session_id: &str) {
    if session_id.is_empty() {
        return;
    }
    let session_id = session_id.to_string();
    if let Err(error) = GuardStore::with_exclusive_lock(|store| {
        store.entries.remove(&session_id);
    }) {
        eprintln!("Warning: Failed to clear background task state: {error}");
    }
}

/// Deny only a blocking TaskOutput call positively correlated to the just
/// completed background Bash start. Missing `block` uses TaskOutput's public
/// default of true; malformed values fail open.
pub fn check_task_output(hook: &HookInput) -> Option<HookOutput> {
    if hook.tool_name != "TaskOutput" || hook.session_id.is_empty() {
        return None;
    }
    let Some(tool_input) = hook.tool_input.as_map() else {
        clear_session(&hook.session_id);
        return None;
    };
    let effective_block = match tool_input.get("block") {
        None => true,
        Some(value) => match value.as_bool() {
            Some(block) => block,
            None => {
                clear_session(&hook.session_id);
                return None;
            }
        },
    };
    if !effective_block {
        return None;
    }
    let Some(task_id) = tool_input
        .get("task_id")
        .and_then(|value| value.as_str())
        .filter(|task_id| !task_id.is_empty())
    else {
        clear_session(&hook.session_id);
        return None;
    };

    let session_id = hook.session_id.clone();
    let matches = match GuardStore::with_exclusive_lock(|store| {
        let matches = store
            .entries
            .get(&session_id)
            .is_some_and(|pending| pending.task_id == task_id);
        if !matches {
            store.entries.remove(&session_id);
        }
        matches
    }) {
        Ok(matches) => matches,
        Err(error) => {
            eprintln!("Warning: Failed to inspect background task state: {error}");
            false
        }
    };
    matches.then(|| {
        HookOutput::deny(
            "A background command was just started for this task. Continue useful independent work, rely on its completion notification, or use TaskOutput with block=false for one status check instead of blocking immediately.",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ToolInputVariant;

    #[serial_test::serial]
    #[test]
    fn persisted_session_state_never_exceeds_the_bound() {
        let cache = tempfile::tempdir().expect("cache tempdir");
        let saved = std::env::var("XDG_CACHE_HOME").ok();
        // SAFETY: The serial guard prevents other env-sensitive tests from
        // observing this process-global override, which is restored below.
        unsafe { std::env::set_var("XDG_CACHE_HOME", cache.path()) };

        for index in 0..=MAX_SESSIONS {
            let mut tool_input = serde_json::Map::new();
            tool_input.insert("command".to_string(), serde_json::json!("my-service watch"));
            tool_input.insert("run_in_background".to_string(), serde_json::json!(true));
            observe_post_tool_use(&PostToolUseInput {
                hook_event_name: "PostToolUse".to_string(),
                session_id: format!("session-{index}"),
                cwd: "/tmp/project".to_string(),
                tool_name: "Bash".to_string(),
                tool_input: ToolInputVariant::Map(tool_input),
                tool_use_id: format!("toolu-{index}"),
                tool_response: Some(serde_json::json!({
                    "backgroundTaskId": format!("task-{index}")
                })),
                effort: None,
            });
        }

        let stored = std::fs::read_to_string(GuardStore::path()).expect("read guard state");
        let store: GuardStore = serde_json::from_str(&stored).expect("parse guard state");
        assert_eq!(store.entries.len(), MAX_SESSIONS);

        unsafe {
            match saved {
                Some(value) => std::env::set_var("XDG_CACHE_HOME", value),
                None => std::env::remove_var("XDG_CACHE_HOME"),
            }
        }
    }
}

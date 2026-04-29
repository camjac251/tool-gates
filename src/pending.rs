//! Pending approvals queue backed by a single global JSONL file.
//!
//! Stores successfully executed commands that the user may want to permanently approve.
//! Uses JSONL format (one JSON object per line) for efficient append-only operations.
//! All entries go to `~/.cache/tool-gates/pending.jsonl` with project directory tracked in `cwd`.

use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, Write};
use std::path::PathBuf;
use uuid::Uuid;

use crate::tracking::CommandPart;

/// A pending approval entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    pub id: String,
    pub command: String,
    pub patterns: Vec<String>,
    pub breakdown: Vec<CommandPart>,
    /// Stable project identifier (extracted from transcript_path or sanitized cwd)
    pub project_id: String,
    /// Original working directory path (for display purposes).
    /// Falls back to project_id if not available (backwards compat with old entries).
    #[serde(default)]
    pub cwd: String,
    pub session_id: String,
    pub count: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl PendingApproval {
    pub fn new(
        command: String,
        patterns: Vec<String>,
        breakdown: Vec<CommandPart>,
        project_id: String,
        cwd: String,
        session_id: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            command,
            patterns,
            breakdown,
            project_id,
            cwd,
            session_id,
            count: 1,
            first_seen: now,
            last_seen: now,
        }
    }

    /// Increment the count and update last_seen
    pub fn increment(&mut self) {
        self.count += 1;
        self.last_seen = Utc::now();
    }
}

/// Get the path to the global pending queue
pub fn pending_path() -> PathBuf {
    crate::cache::cache_dir().join("pending.jsonl")
}

/// Read all pending approvals from the global JSONL file.
/// Optionally filter by project_id.
pub fn read_pending(filter_project: Option<&str>) -> Vec<PendingApproval> {
    let path = pending_path();

    if !path.exists() {
        return Vec::new();
    }

    let file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    // Blocking shared lock for reading - don't silently fail
    #[allow(clippy::incompatible_msrv)] // fs2 crate method, not std
    if file.lock_shared().is_err() {
        eprintln!("Warning: Could not acquire lock on pending file");
        return Vec::new();
    }

    let reader = BufReader::new(&file);
    let mut entries = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        if let Ok(entry) = serde_json::from_str::<PendingApproval>(&line) {
            // Filter by project_id if specified
            if let Some(project) = filter_project {
                if entry.project_id == project {
                    entries.push(entry);
                }
            } else {
                entries.push(entry);
            }
        }
    }

    #[allow(clippy::incompatible_msrv)] // fs2 crate method, not std
    let _ = file.unlock();

    entries
}

/// Atomically modify the pending approvals file.
/// Holds exclusive lock for entire read-modify-write to prevent race conditions.
fn with_exclusive_pending<F, R>(f: F) -> std::io::Result<R>
where
    F: FnOnce(&mut Vec<PendingApproval>) -> R,
{
    let path = pending_path();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Open file for read+write with exclusive lock
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;

    #[allow(clippy::incompatible_msrv)] // fs2 crate method, not std
    file.lock_exclusive()?;

    // Read current contents
    let reader = BufReader::new(&file);
    let mut entries = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        if let Ok(entry) = serde_json::from_str::<PendingApproval>(&line) {
            entries.push(entry);
        }
    }

    // Execute the modification function
    let result = f(&mut entries);

    // Write back - truncate and seek to start
    file.set_len(0)?;
    file.seek(std::io::SeekFrom::Start(0))?;

    let mut writer = std::io::BufWriter::new(&file);
    for entry in &entries {
        let json = serde_json::to_string(entry)?;
        writeln!(writer, "{}", json)?;
    }
    writer.flush()?;

    #[allow(clippy::incompatible_msrv)] // fs2 crate method, not std
    file.unlock()?;

    Ok(result)
}

/// Append a pending approval (or increment if same command already exists).
///
/// Compaction strategy:
///   1. Exact match on `(command, project_id)` -> increment, refresh patterns
///      and breakdown. Self-heals stale per-subcommand attribution.
///   2. Pattern-key match on `(compaction_key, project_id)` -> increment the
///      existing entry, intersect the pattern lists so the kept pattern is
///      the broadest one shared by both commands. Lets `npm install foo`
///      and `npm install bar` collapse to a single `npm install:*` entry
///      instead of polluting the queue with one row per package.
///   3. Otherwise append as a new entry.
pub fn append_pending(approval: PendingApproval) -> std::io::Result<()> {
    with_exclusive_pending(|entries| {
        // Tier 1: exact command match in same project.
        if let Some(existing) = entries
            .iter_mut()
            .find(|e| e.command == approval.command && e.project_id == approval.project_id)
        {
            existing.increment();
            existing.patterns = approval.patterns;
            existing.breakdown = approval.breakdown;
            return;
        }

        // Tier 2: compaction-key match in same project. Collapses near-duplicates
        // that differ only in trailing literal args (package names, PR numbers).
        if let Some(new_key) = compaction_key(&approval.patterns) {
            if let Some(existing) = entries.iter_mut().find(|e| {
                e.project_id == approval.project_id
                    && compaction_key(&e.patterns).as_deref() == Some(new_key.as_str())
            }) {
                existing.increment();
                // Keep only patterns shared by both. The broadest matching
                // pattern survives; the specific-literal patterns drop out.
                let new_set: std::collections::HashSet<&String> =
                    approval.patterns.iter().collect();
                existing.patterns.retain(|p| new_set.contains(p));
                // Don't replace breakdown -- the existing entry's breakdown
                // already corresponds to its command, and the new command
                // would be misleading there.
                return;
            }
        }

        entries.push(approval);
    })
}

/// Returns a stable key that lets near-duplicates collapse into one
/// pending entry. Walks from broadest to narrowest:
/// 1. A subcommand-scoped glob (`<program> <subcommand>:*`) is the ideal
///    key because it groups variations of the same subcommand.
/// 2. A program-only glob (`<program>:*`) groups everything for the
///    program when no subcommand glob is on offer (e.g. mise shorthand
///    only emits `[literal, mise:*]`).
/// 3. Otherwise the last pattern as a stable-ish fallback.
fn compaction_key(patterns: &[String]) -> Option<String> {
    if patterns.is_empty() {
        return None;
    }
    if patterns.len() == 1 {
        return Some(patterns[0].clone());
    }

    if let Some(p) = patterns
        .iter()
        .rfind(|p| p.ends_with(":*") && p.contains(' '))
    {
        return Some(p.clone());
    }
    if let Some(p) = patterns.iter().rfind(|p| p.ends_with(":*")) {
        return Some(p.clone());
    }
    Some(patterns[patterns.len() - 1].clone())
}

/// Remove a pending approval by ID
pub fn remove_pending(id: &str) -> std::io::Result<bool> {
    with_exclusive_pending(|entries| {
        let len_before = entries.len();
        entries.retain(|e| e.id != id);
        entries.len() < len_before
    })
}

/// Remove multiple pending approvals by ID
pub fn remove_pending_many(ids: &[String]) -> std::io::Result<usize> {
    with_exclusive_pending(|entries| {
        let len_before = entries.len();
        let id_set: std::collections::HashSet<&str> = ids.iter().map(|s| s.as_str()).collect();
        entries.retain(|e| !id_set.contains(e.id.as_str()));
        len_before - entries.len()
    })
}

/// Clear pending approvals, optionally filtered by project
pub fn clear_pending(filter_project: Option<&str>) -> std::io::Result<usize> {
    with_exclusive_pending(|entries| {
        let len_before = entries.len();
        match filter_project {
            None => {
                entries.clear();
            }
            Some(project) => {
                entries.retain(|e| e.project_id != project);
            }
        }
        len_before - entries.len()
    })
}

/// Get pending approvals grouped by command pattern
pub fn pending_stats(filter_project: Option<&str>) -> HashMap<String, u32> {
    let entries = read_pending(filter_project);
    let mut stats = HashMap::new();

    for entry in entries {
        *stats.entry(entry.command.clone()).or_insert(0) += entry.count;
    }

    stats
}

/// Get total count of pending approvals
pub fn pending_count(filter_project: Option<&str>) -> usize {
    read_pending(filter_project).len()
}

/// Project information for the sidebar
#[derive(Debug, Clone)]
pub struct ProjectInfo {
    /// Short name (last directory component)
    pub name: String,
    /// Display path (with ~ for home)
    pub display_path: String,
    /// Real filesystem path (for settings writer)
    pub cwd: String,
    /// Number of pending entries in this project
    pub count: usize,
}

/// Derive unique projects from pending entries, sorted by count descending
pub fn derive_projects(entries: &[PendingApproval]) -> Vec<ProjectInfo> {
    let mut projects: HashMap<String, ProjectInfo> = HashMap::new();

    for entry in entries {
        let display = display_project_path(entry);
        let name = display.rsplit('/').next().unwrap_or(&display).to_string();

        let project = projects
            .entry(display.clone())
            .or_insert_with(|| ProjectInfo {
                name,
                display_path: display.clone(),
                cwd: if entry.cwd.is_empty() {
                    entry.project_id.clone()
                } else {
                    entry.cwd.clone()
                },
                count: 0,
            });
        project.count += 1;
    }

    let mut result: Vec<ProjectInfo> = projects.into_values().collect();
    result.sort_by_key(|b| std::cmp::Reverse(b.count));
    result
}

/// Category weight for command sorting (lower = higher priority)
///
/// Package managers and build tools first (most friction from repeated approvals),
/// then task runners, dev tools, git, and finally network/cloud/system commands.
pub fn category_weight(command: &str) -> u8 {
    let program = command.split_whitespace().next().unwrap_or("");
    match program {
        "cargo" | "npm" | "pnpm" | "yarn" | "bun" | "pip" | "pip3" | "uv" | "poetry" | "go"
        | "rustc" | "rustup" => 0,
        "mise" | "make" | "just" => 1,
        "biome" | "prettier" | "eslint" | "ruff" | "black" | "rustfmt" | "gofmt" | "shfmt"
        | "sg" | "ast-grep" | "sd" | "jq" | "yq" | "semgrep" => 2,
        "git" => 3,
        "gh" => 4,
        "curl" | "wget" | "ssh" | "scp" | "rsync" => 5,
        "aws" | "gcloud" | "az" | "kubectl" | "docker" | "terraform" | "pulumi" | "helm" => 6,
        _ => 7,
    }
}

/// Get a human-readable display path for a pending approval entry.
///
/// Uses the stored `cwd` field (real path) when available, falling back
/// to `project_id` as-is for old entries that lack `cwd`.
/// Collapses the home directory prefix to `~` for brevity.
pub fn display_project_path(entry: &PendingApproval) -> String {
    let path = if entry.cwd.is_empty() {
        // Backwards compat: old entries without cwd field.
        // project_id is already a sanitized identifier, show it as-is.
        return entry.project_id.clone();
    } else {
        &entry.cwd
    };

    // Collapse home directory prefix to ~
    if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy();
        if path.starts_with(home_str.as_ref()) {
            return path.replacen(home_str.as_ref(), "~", 1);
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_approval_creation() {
        let approval = PendingApproval::new(
            "npm install".to_string(),
            vec!["npm install:*".to_string()],
            vec![],
            "/tmp".to_string(),
            "/tmp".to_string(),
            "session1".to_string(),
        );

        assert_eq!(approval.command, "npm install");
        assert_eq!(approval.count, 1);
        assert!(!approval.id.is_empty());
    }

    #[test]
    fn test_pending_increment() {
        let mut approval = PendingApproval::new(
            "npm install".to_string(),
            vec![],
            vec![],
            "/tmp".to_string(),
            "/tmp".to_string(),
            "session1".to_string(),
        );

        approval.increment();
        assert_eq!(approval.count, 2);
    }

    #[test]
    fn test_pending_path() {
        let path = pending_path();
        assert!(path.ends_with("tool-gates/pending.jsonl"));
    }

    // Integration tests for file I/O are in tests/pending_integration.rs
    // These unit tests focus on struct logic only to avoid test isolation issues

    // --- Bug fix regression tests ---

    /// Helper: simulate the read_pending filter logic (mirrors the filter inside read_pending)
    fn filter_entries(
        entries: &[PendingApproval],
        filter_project: Option<&str>,
    ) -> Vec<PendingApproval> {
        entries
            .iter()
            .filter(|entry| match filter_project {
                Some(project) => entry.project_id == project,
                None => true,
            })
            .cloned()
            .collect()
    }

    /// Helper: simulate the append_pending dedup logic (mirrors the closure inside append_pending)
    fn simulate_append(entries: &mut Vec<PendingApproval>, approval: PendingApproval) {
        // Tier 1: exact command + project match
        if let Some(existing) = entries
            .iter_mut()
            .find(|e| e.command == approval.command && e.project_id == approval.project_id)
        {
            existing.increment();
            existing.patterns = approval.patterns;
            existing.breakdown = approval.breakdown;
            return;
        }

        // Tier 2: compaction-key match
        if let Some(new_key) = compaction_key(&approval.patterns) {
            if let Some(existing) = entries.iter_mut().find(|e| {
                e.project_id == approval.project_id
                    && compaction_key(&e.patterns).as_deref() == Some(new_key.as_str())
            }) {
                existing.increment();
                let new_set: std::collections::HashSet<&String> =
                    approval.patterns.iter().collect();
                existing.patterns.retain(|p| new_set.contains(p));
                return;
            }
        }

        entries.push(approval);
    }

    /// Helper: simulate the clear_pending logic (mirrors the closure inside clear_pending)
    fn simulate_clear(entries: &mut Vec<PendingApproval>, filter_project: Option<&str>) -> usize {
        let len_before = entries.len();
        match filter_project {
            None => entries.clear(),
            Some(project) => entries.retain(|e| e.project_id != project),
        }
        len_before - entries.len()
    }

    fn make_approval(command: &str, project_id: &str) -> PendingApproval {
        PendingApproval::new(
            command.to_string(),
            vec![],
            vec![],
            project_id.to_string(),
            String::new(),
            "sess".to_string(),
        )
    }

    // Bug 2: project filter must use exact equality, not substring contains

    #[test]
    fn test_read_filter_exact_match_only() {
        let entries = vec![
            make_approval("cmd1", "app"),
            make_approval("cmd2", "happy"),
            make_approval("cmd3", "webapp"),
            make_approval("cmd4", "app"),
        ];

        let filtered = filter_entries(&entries, Some("app"));
        assert_eq!(
            filtered.len(),
            2,
            "should match only exact 'app', not 'happy' or 'webapp'"
        );
        assert!(filtered.iter().all(|e| e.project_id == "app"));
    }

    #[test]
    fn test_read_filter_no_substring_match() {
        let entries = vec![
            make_approval("cmd1", "happy"),
            make_approval("cmd2", "webapp"),
            make_approval("cmd3", "application"),
        ];

        let filtered = filter_entries(&entries, Some("app"));
        assert_eq!(
            filtered.len(),
            0,
            "substring matches like 'happy', 'webapp', 'application' must not match 'app'"
        );
    }

    #[test]
    fn test_read_filter_none_returns_all() {
        let entries = vec![
            make_approval("cmd1", "proj-a"),
            make_approval("cmd2", "proj-b"),
        ];

        let filtered = filter_entries(&entries, None);
        assert_eq!(filtered.len(), 2);
    }

    // Bug 3: dedup must include project_id, not just command

    #[test]
    fn test_append_dedup_same_project_increments() {
        let mut entries = Vec::new();

        simulate_append(&mut entries, make_approval("npm install", "proj-a"));
        simulate_append(&mut entries, make_approval("npm install", "proj-a"));

        assert_eq!(entries.len(), 1, "same command + same project should dedup");
        assert_eq!(entries[0].count, 2);
    }

    #[test]
    fn test_append_dedup_different_projects_keeps_both() {
        let mut entries = Vec::new();

        simulate_append(&mut entries, make_approval("npm install", "proj-a"));
        simulate_append(&mut entries, make_approval("npm install", "proj-b"));

        assert_eq!(
            entries.len(),
            2,
            "same command in different projects must create separate entries"
        );
        assert_eq!(entries[0].count, 1);
        assert_eq!(entries[1].count, 1);
        assert_eq!(entries[0].project_id, "proj-a");
        assert_eq!(entries[1].project_id, "proj-b");
    }

    #[test]
    fn test_append_dedup_different_commands_same_project() {
        let mut entries = Vec::new();

        simulate_append(&mut entries, make_approval("npm install", "proj-a"));
        simulate_append(&mut entries, make_approval("npm test", "proj-a"));

        assert_eq!(
            entries.len(),
            2,
            "different commands in same project are separate"
        );
    }

    fn make_approval_with_patterns(
        command: &str,
        project_id: &str,
        patterns: &[&str],
    ) -> PendingApproval {
        PendingApproval::new(
            command.to_string(),
            patterns.iter().map(|s| s.to_string()).collect(),
            vec![],
            project_id.to_string(),
            String::new(),
            "sess".to_string(),
        )
    }

    #[test]
    fn test_compaction_key_picks_second_to_last_for_three_patterns() {
        let p = vec![
            "npm install foo".to_string(),
            "npm install:*".to_string(),
            "npm:*".to_string(),
        ];
        assert_eq!(compaction_key(&p).as_deref(), Some("npm install:*"));
    }

    #[test]
    fn test_compaction_key_picks_first_for_two_patterns() {
        let p = vec!["mytool sub:*".to_string(), "mytool:*".to_string()];
        assert_eq!(compaction_key(&p).as_deref(), Some("mytool sub:*"));
    }

    #[test]
    fn test_compaction_key_singleton_returns_only_pattern() {
        let p = vec!["prettier:*".to_string()];
        assert_eq!(compaction_key(&p).as_deref(), Some("prettier:*"));
    }

    #[test]
    fn test_compaction_key_empty_returns_none() {
        let p: Vec<String> = vec![];
        assert!(compaction_key(&p).is_none());
    }

    #[test]
    fn test_compaction_key_git_checkout_two_patterns() {
        // suggest_patterns intentionally omits "git:*" for git checkout/switch
        // (too broad for VCS), so the patterns list is [literal, "git checkout:*"].
        // Compaction must pick the glob, not the literal, so different branches
        // collapse into a single pending entry.
        let p = vec![
            "git checkout main".to_string(),
            "git checkout:*".to_string(),
        ];
        assert_eq!(compaction_key(&p).as_deref(), Some("git checkout:*"));
    }

    #[test]
    fn test_compaction_key_mise_shorthand_two_patterns() {
        // mise shorthand emits [literal, "mise:*"] with no subcommand glob.
        // Different tasks must collapse, so we pick "mise:*" (the only glob).
        let p = vec!["mise lint".to_string(), "mise:*".to_string()];
        assert_eq!(compaction_key(&p).as_deref(), Some("mise:*"));
    }

    #[test]
    fn test_append_collapses_git_checkout_branches() {
        let mut entries = Vec::new();
        simulate_append(
            &mut entries,
            make_approval_with_patterns(
                "git checkout main",
                "proj",
                &["git checkout main", "git checkout:*"],
            ),
        );
        simulate_append(
            &mut entries,
            make_approval_with_patterns(
                "git checkout dev",
                "proj",
                &["git checkout dev", "git checkout:*"],
            ),
        );

        assert_eq!(
            entries.len(),
            1,
            "git checkout main and git checkout dev should collapse"
        );
        assert!(
            entries[0].patterns.iter().any(|p| p == "git checkout:*"),
            "compacted entry should keep the shared subcommand glob"
        );
    }

    #[test]
    fn test_append_collapses_pkg_install_variants() {
        let mut entries = Vec::new();
        simulate_append(
            &mut entries,
            make_approval_with_patterns(
                "npm install foo",
                "proj",
                &["npm install foo", "npm install:*", "npm:*"],
            ),
        );
        simulate_append(
            &mut entries,
            make_approval_with_patterns(
                "npm install bar",
                "proj",
                &["npm install bar", "npm install:*", "npm:*"],
            ),
        );
        simulate_append(
            &mut entries,
            make_approval_with_patterns(
                "npm install baz",
                "proj",
                &["npm install baz", "npm install:*", "npm:*"],
            ),
        );

        assert_eq!(entries.len(), 1, "three install variants must collapse");
        let entry = &entries[0];
        assert_eq!(entry.count, 3);
        assert_eq!(
            entry.patterns,
            vec!["npm install:*".to_string(), "npm:*".to_string()],
            "specific-literal patterns drop out, broad shared patterns remain"
        );
    }

    #[test]
    fn test_append_does_not_collapse_different_subcommands() {
        let mut entries = Vec::new();
        simulate_append(
            &mut entries,
            make_approval_with_patterns(
                "npm install foo",
                "proj",
                &["npm install foo", "npm install:*", "npm:*"],
            ),
        );
        simulate_append(
            &mut entries,
            make_approval_with_patterns("npm test", "proj", &["npm test:*", "npm:*"]),
        );

        assert_eq!(
            entries.len(),
            2,
            "install and test have different compaction keys"
        );
    }

    #[test]
    fn test_append_does_not_collapse_across_projects() {
        let mut entries = Vec::new();
        simulate_append(
            &mut entries,
            make_approval_with_patterns(
                "npm install foo",
                "proj-a",
                &["npm install foo", "npm install:*", "npm:*"],
            ),
        );
        simulate_append(
            &mut entries,
            make_approval_with_patterns(
                "npm install bar",
                "proj-b",
                &["npm install bar", "npm install:*", "npm:*"],
            ),
        );

        assert_eq!(entries.len(), 2, "compaction must respect project_id");
    }

    #[test]
    fn test_append_no_patterns_falls_through_to_tier1_only() {
        // Backwards-compat: entries without patterns (legacy) only dedup on
        // exact command match.
        let mut entries = Vec::new();
        simulate_append(&mut entries, make_approval("cmd a", "proj"));
        simulate_append(&mut entries, make_approval("cmd b", "proj"));
        assert_eq!(entries.len(), 2);
    }

    // Bug 1: clear_pending(None) must use with_exclusive_pending (tested via simulate logic)

    #[test]
    fn test_clear_none_removes_all_entries() {
        let mut entries = vec![
            make_approval("cmd1", "proj-a"),
            make_approval("cmd2", "proj-b"),
            make_approval("cmd3", "proj-c"),
        ];

        let removed = simulate_clear(&mut entries, None);
        assert_eq!(removed, 3);
        assert!(entries.is_empty(), "clear(None) must empty the entire vec");
    }

    #[test]
    fn test_clear_project_filter_exact_only() {
        let mut entries = vec![
            make_approval("cmd1", "app"),
            make_approval("cmd2", "happy"),
            make_approval("cmd3", "webapp"),
            make_approval("cmd4", "app"),
        ];

        let removed = simulate_clear(&mut entries, Some("app"));
        assert_eq!(removed, 2, "should only remove exact 'app' matches");
        assert_eq!(entries.len(), 2);
        assert!(
            entries.iter().all(|e| e.project_id != "app"),
            "no 'app' entries should remain"
        );
        assert!(
            entries.iter().any(|e| e.project_id == "happy"),
            "'happy' must not be removed when filtering by 'app'"
        );
        assert!(
            entries.iter().any(|e| e.project_id == "webapp"),
            "'webapp' must not be removed when filtering by 'app'"
        );
    }

    #[test]
    fn test_clear_project_filter_no_match() {
        let mut entries = vec![
            make_approval("cmd1", "proj-a"),
            make_approval("cmd2", "proj-b"),
        ];

        let removed = simulate_clear(&mut entries, Some("proj-c"));
        assert_eq!(removed, 0);
        assert_eq!(entries.len(), 2);
    }

    // --- Lossy project_id encoding regression tests ---

    /// Helper to create an approval with both project_id and cwd
    fn make_approval_with_cwd(command: &str, project_id: &str, cwd: &str) -> PendingApproval {
        PendingApproval::new(
            command.to_string(),
            vec![],
            vec![],
            project_id.to_string(),
            cwd.to_string(),
            "sess".to_string(),
        )
    }

    #[test]
    fn test_display_project_path_uses_cwd_when_available() {
        let entry = make_approval_with_cwd("cmd", "-home-user-my-project", "/home/user/my-project");
        // Should use the real cwd, not try to decode project_id
        let display = display_project_path(&entry);
        assert!(
            display.contains("my-project"),
            "display path should preserve hyphens from real cwd: got '{display}'"
        );
        // Should NOT contain "my/project" (the old lossy decoding bug)
        assert!(
            !display.contains("my/project"),
            "display path must not lossy-decode hyphens as slashes: got '{display}'"
        );
    }

    #[test]
    fn test_display_project_path_falls_back_to_project_id_for_old_entries() {
        // Old entries without cwd field (empty string from #[serde(default)])
        let entry = make_approval_with_cwd("cmd", "-home-user-my-project", "");
        let display = display_project_path(&entry);
        assert_eq!(
            display, "-home-user-my-project",
            "old entries without cwd should show project_id as-is"
        );
    }

    #[test]
    fn test_display_project_path_absolute_path_outside_home() {
        let entry = make_approval_with_cwd("cmd", "-opt-myapp", "/opt/myapp");
        let display = display_project_path(&entry);
        assert_eq!(display, "/opt/myapp");
    }

    #[test]
    fn test_serde_round_trip_with_cwd() {
        let approval = make_approval_with_cwd(
            "npm install",
            "-home-user-my-project",
            "/home/user/my-project",
        );
        let json = serde_json::to_string(&approval).unwrap();
        let restored: PendingApproval = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.cwd, "/home/user/my-project");
        assert_eq!(restored.project_id, "-home-user-my-project");
    }

    #[test]
    fn test_serde_backwards_compat_missing_cwd() {
        // Simulate an old JSONL entry that lacks the cwd field
        let json = r#"{"id":"test-id","command":"npm install","patterns":[],"breakdown":[],"project_id":"-home-user-my-project","session_id":"s","count":1,"first_seen":"2025-01-01T00:00:00Z","last_seen":"2025-01-01T00:00:00Z"}"#;
        let entry: PendingApproval = serde_json::from_str(json).unwrap();
        assert_eq!(entry.cwd, "", "missing cwd should default to empty string");
        assert_eq!(entry.project_id, "-home-user-my-project");
        // display_project_path should fall back gracefully
        let display = display_project_path(&entry);
        assert_eq!(display, "-home-user-my-project");
    }
}

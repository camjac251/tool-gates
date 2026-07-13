//! On-disk integration tests for the pending approval queue.

use serial_test::serial;
use std::ffi::OsString;
use std::io::Write;
use tool_gates::pending::{
    PendingApproval, append_pending, clear_pending, pending_path, read_pending, remove_pending,
    remove_pending_many,
};

struct IsolatedCache {
    _temp: tempfile::TempDir,
    previous: Option<OsString>,
}

impl IsolatedCache {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("cache tempdir");
        let previous = std::env::var_os("XDG_CACHE_HOME");
        unsafe { std::env::set_var("XDG_CACHE_HOME", temp.path()) };
        Self {
            _temp: temp,
            previous,
        }
    }
}

impl Drop for IsolatedCache {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => unsafe { std::env::set_var("XDG_CACHE_HOME", value) },
            None => unsafe { std::env::remove_var("XDG_CACHE_HOME") },
        }
    }
}

fn approval(command: &str, project: &str, patterns: &[&str]) -> PendingApproval {
    PendingApproval::new(
        command.to_string(),
        patterns.iter().map(|pattern| pattern.to_string()).collect(),
        vec![],
        project.to_string(),
        format!("/tmp/{project}"),
        "session-test".to_string(),
    )
}

#[test]
#[serial]
fn pending_queue_persists_filters_and_skips_malformed_lines() {
    let _cache = IsolatedCache::new();

    append_pending(approval("mytool deploy", "app", &["mytool deploy:*"]))
        .expect("append app entry");
    append_pending(approval("mytool deploy", "app", &["mytool deploy:*"]))
        .expect("increment app entry");
    append_pending(approval("mytool deploy", "happy", &["mytool deploy:*"]))
        .expect("append happy entry");

    let app = read_pending(Some("app"));
    assert_eq!(app.len(), 1, "project filters must use exact equality");
    assert_eq!(app[0].count, 2, "exact command matches must persist counts");

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(pending_path())
        .expect("open pending queue");
    writeln!(file, "{{not-json").expect("append malformed line");

    let entries = read_pending(None);
    assert_eq!(entries.len(), 2, "malformed lines must be ignored");
    assert!(remove_pending(&app[0].id).expect("remove app entry"));
    assert!(!remove_pending(&app[0].id).expect("remove missing app entry"));
    assert_eq!(read_pending(None).len(), 1);
}

#[test]
#[serial]
fn pending_queue_compacts_patterns_and_removes_many() {
    let _cache = IsolatedCache::new();

    append_pending(approval(
        "mytool install first",
        "project-a",
        &["mytool install first", "mytool install:*", "mytool:*"],
    ))
    .expect("append first variant");
    append_pending(approval(
        "mytool install second",
        "project-a",
        &["mytool install second", "mytool install:*", "mytool:*"],
    ))
    .expect("append second variant");
    append_pending(approval(
        "mytool test",
        "project-a",
        &["mytool test:*", "mytool:*"],
    ))
    .expect("append distinct subcommand");

    let entries = read_pending(None);
    assert_eq!(
        entries.len(),
        2,
        "matching subcommand patterns must compact"
    );
    let compacted = entries
        .iter()
        .find(|entry| entry.command == "mytool install first")
        .expect("compacted install entry");
    assert_eq!(compacted.count, 2);
    assert_eq!(
        compacted.patterns,
        vec!["mytool install:*".to_string(), "mytool:*".to_string()]
    );

    let ids = entries
        .iter()
        .map(|entry| entry.id.clone())
        .collect::<Vec<_>>();
    assert_eq!(remove_pending_many(&ids).expect("remove entries"), 2);
    assert!(read_pending(None).is_empty());
}

#[test]
#[serial]
fn pending_queue_serializes_concurrent_appends_and_clears_exact_projects() {
    let _cache = IsolatedCache::new();

    let threads = (0..12)
        .map(|_| {
            std::thread::spawn(|| {
                append_pending(approval("mytool deploy", "app", &["mytool deploy:*"]))
                    .expect("append concurrent entry");
            })
        })
        .collect::<Vec<_>>();
    for thread in threads {
        thread.join().expect("join append thread");
    }

    append_pending(approval(
        "mytool deploy",
        "application",
        &["mytool deploy:*"],
    ))
    .expect("append neighboring project");

    let app = read_pending(Some("app"));
    assert_eq!(app.len(), 1);
    assert_eq!(app[0].count, 12, "concurrent appends must not lose updates");
    assert_eq!(clear_pending(Some("app")).expect("clear app project"), 1);

    let remaining = read_pending(None);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].project_id, "application");
    assert_eq!(clear_pending(None).expect("clear all projects"), 1);
    assert!(read_pending(None).is_empty());
}

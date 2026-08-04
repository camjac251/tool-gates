//! Real-binary persistence tests for client hook installers.

use std::ffi::OsStr;
use std::process::{Command, Output};

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_tool-gates")
}

#[derive(Clone, Copy)]
struct InstallerCase {
    name: &'static str,
    flag: Option<&'static str>,
    relative_path: &'static str,
    named_hooks: bool,
}

const CASES: &[InstallerCase] = &[
    InstallerCase {
        name: "claude",
        flag: None,
        relative_path: "claude/settings.json",
        named_hooks: false,
    },
    InstallerCase {
        name: "gemini",
        flag: Some("--gemini"),
        relative_path: ".gemini/settings.json",
        named_hooks: false,
    },
    InstallerCase {
        name: "codex",
        flag: Some("--codex"),
        relative_path: ".codex/hooks.json",
        named_hooks: false,
    },
    InstallerCase {
        name: "antigravity",
        flag: Some("--antigravity"),
        relative_path: ".gemini/config/hooks.json",
        named_hooks: true,
    },
];

fn run_installer(case: InstallerCase, root: &std::path::Path) -> Output {
    let mut command = Command::new(bin_path());
    command.args(["hooks", "add", "-s", "user"]);
    if let Some(flag) = case.flag {
        command.arg(flag);
    }
    command
        .current_dir(root)
        .env("HOME", root)
        .env("CLAUDE_CONFIG_DIR", root.join("claude"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env_remove("CLAUDE_PROJECT_DIR")
        .env_remove("GEMINI_PROJECT_DIR")
        .output()
        .unwrap_or_else(|error| panic!("spawn {} installer: {error}", case.name))
}

fn run_allowlist(root: &std::path::Path) -> Output {
    Command::new(bin_path())
        .args(["agy", "allowlist", "--apply"])
        .current_dir(root)
        .env("HOME", root)
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .output()
        .expect("spawn allowlist command")
}

fn config_path(case: InstallerCase, root: &std::path::Path) -> std::path::PathBuf {
    root.join(case.relative_path)
}

fn backup_paths(path: &std::path::Path) -> Vec<std::path::PathBuf> {
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .expect("config file name");
    let prefix = format!("{file_name}.backup-");
    path.parent()
        .expect("config parent")
        .read_dir()
        .expect("read config parent")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .map(|entry| entry.path())
        .collect()
}

fn assert_success(case: InstallerCase, output: &Output) {
    assert!(
        output.status.success(),
        "{} installer failed: {}",
        case.name,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn hook_installers_preserve_config_backup_permissions_and_idempotence() {
    for case in CASES.iter().copied() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = config_path(case, temp.path());
        std::fs::create_dir_all(path.parent().expect("config parent"))
            .expect("create config parent");
        let original = if case.named_hooks {
            br#"{"custom-hook":{"PreToolUse":[]}}"#.as_slice()
        } else {
            br#"{"other":{"preserved":true},"hooks":{"CustomEvent":[{"matcher":"mytool","hooks":[]}]}}"#.as_slice()
        };
        std::fs::write(&path, original).expect("seed config");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
                .expect("set config mode");
        }

        let first = run_installer(case, temp.path());
        assert_success(case, &first);
        let first_bytes = std::fs::read(&path).expect("read installed config");
        let root: serde_json::Value =
            serde_json::from_slice(&first_bytes).expect("installed config is valid JSON");
        if case.named_hooks {
            assert!(root.get("custom-hook").is_some());
            assert!(root.get("tool-gates").is_some());
        } else {
            assert_eq!(root["other"]["preserved"], true);
            assert!(root["hooks"].get("CustomEvent").is_some());
            if case.name == "claude" {
                let hooks = root["hooks"].as_object().expect("Claude hooks object");
                assert!(hooks.contains_key("UserPromptSubmit"));
                let pre_matcher = hooks["PreToolUse"][0]["matcher"]
                    .as_str()
                    .expect("Claude PreToolUse matcher");
                assert!(pre_matcher.split('|').any(|tool| tool == "TaskOutput"));
                let post = hooks["PostToolUse"]
                    .as_array()
                    .expect("Claude PostToolUse entries");
                assert_eq!(post.len(), 1);
                assert!(
                    post[0].get("matcher").is_none(),
                    "Claude PostToolUse must observe successful work from every tool"
                );
            }
        }

        let backups = backup_paths(&path);
        assert_eq!(backups.len(), 1, "{} must retain one backup", case.name);
        assert_eq!(std::fs::read(&backups[0]).expect("read backup"), original);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("config metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o640,
                "{} must preserve config permissions",
                case.name
            );
        }

        let second = run_installer(case, temp.path());
        assert_success(case, &second);
        assert_eq!(
            std::fs::read(&path).expect("read idempotent config"),
            first_bytes,
            "{} second install must not rewrite the file",
            case.name
        );
        assert_eq!(
            backup_paths(&path).len(),
            1,
            "{} second install must not create another backup",
            case.name
        );
    }
}

#[test]
fn hook_installers_leave_malformed_json_untouched() {
    for case in CASES.iter().copied() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = config_path(case, temp.path());
        std::fs::create_dir_all(path.parent().expect("config parent"))
            .expect("create config parent");
        let original = b"{not-json";
        std::fs::write(&path, original).expect("seed malformed config");

        let output = run_installer(case, temp.path());
        assert!(
            !output.status.success(),
            "{} malformed config must fail",
            case.name
        );
        assert_eq!(
            std::fs::read(&path).expect("read malformed config"),
            original,
            "{} malformed bytes must remain exact",
            case.name
        );
        assert!(
            backup_paths(&path).is_empty(),
            "{} must not back up when no write is attempted",
            case.name
        );
    }
}

#[test]
fn antigravity_allowlist_uses_the_same_transaction_contract() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join(".gemini/antigravity-cli/settings.json");
    std::fs::create_dir_all(path.parent().expect("settings parent"))
        .expect("create settings parent");
    let original = br#"{"permissions":{"allow":["command(existing)"],"deny":["command(blocked)"]},"other":true}"#;
    std::fs::write(&path, original).expect("seed settings");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("set settings mode");
    }

    let first = run_allowlist(temp.path());
    assert!(
        first.status.success(),
        "allowlist update failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_bytes = std::fs::read(&path).expect("read updated settings");
    let settings: serde_json::Value =
        serde_json::from_slice(&first_bytes).expect("updated settings are valid");
    assert_eq!(settings["other"], true);
    assert!(
        settings["permissions"]["deny"]
            .as_array()
            .expect("deny array")
            .iter()
            .any(|value| value == "command(blocked)")
    );
    assert!(
        settings["permissions"]["allow"]
            .as_array()
            .expect("allow array")
            .iter()
            .any(|value| value == "command(existing)")
    );
    let backups = backup_paths(&path);
    assert_eq!(backups.len(), 1);
    assert_eq!(std::fs::read(&backups[0]).expect("read backup"), original);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path)
                .expect("settings metadata")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }

    let second = run_allowlist(temp.path());
    assert!(second.status.success());
    assert_eq!(std::fs::read(&path).expect("read settings"), first_bytes);
    assert_eq!(backup_paths(&path).len(), 1);
}

#[test]
fn antigravity_allowlist_preserves_malformed_json() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join(".gemini/antigravity-cli/settings.json");
    std::fs::create_dir_all(path.parent().expect("settings parent"))
        .expect("create settings parent");
    let original = b"{not-json";
    std::fs::write(&path, original).expect("seed malformed settings");

    let output = run_allowlist(temp.path());
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&path).expect("read settings"), original);
    assert!(backup_paths(&path).is_empty());
}

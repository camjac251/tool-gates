//! Settings writer for modifying Claude Code settings.json files.
//!
//! Supports adding and removing permission rules from settings files.

use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

/// Scope for settings files
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    User,
    Project,
    Local,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Self::User),
            "project" => Some(Self::Project),
            "local" => Some(Self::Local),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
            Self::Local => "local",
        }
    }

    pub fn path(&self) -> PathBuf {
        match self {
            Self::User => {
                // Check CLAUDE_CONFIG_DIR env var first, fall back to ~/.claude
                let config_dir = std::env::var("CLAUDE_CONFIG_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| {
                        dirs::home_dir()
                            .unwrap_or_else(|| PathBuf::from("."))
                            .join(".claude")
                    });
                config_dir.join("settings.json")
            }
            Self::Project | Self::Local => {
                // Resolve to absolute path at call time to avoid issues if cwd changes
                let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                let filename = match self {
                    Self::Project => "settings.json",
                    Self::Local => "settings.local.json",
                    _ => unreachable!(),
                };
                cwd.join(".claude").join(filename)
            }
        }
    }

    /// Get the settings file path for a specific project directory
    pub fn path_for_project(&self, project_path: &str) -> PathBuf {
        match self {
            Self::User => self.path(), // User scope ignores project
            Self::Project => PathBuf::from(project_path)
                .join(".claude")
                .join("settings.json"),
            Self::Local => PathBuf::from(project_path)
                .join(".claude")
                .join("settings.local.json"),
        }
    }
}

/// Type of permission rule
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleType {
    Allow,
    Ask,
    Deny,
}

impl RuleType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

/// A permission rule from settings.json
#[derive(Debug, Clone)]
pub struct PermissionRule {
    pub pattern: String,
    pub rule_type: RuleType,
    pub scope: Scope,
}

/// Load settings from a scope, returning empty object if not found
fn load_settings(scope: Scope) -> Value {
    let path = scope.path();
    if !path.exists() {
        return json!({});
    }

    fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

/// Atomically modify settings with exclusive lock.
/// Holds the lock for the entire read-modify-write operation to prevent race conditions.
fn with_exclusive_settings<F, R>(scope: Scope, f: F) -> std::io::Result<R>
where
    F: FnOnce(&mut Value) -> R,
{
    with_exclusive_settings_path(&scope.path(), f)
}

/// Atomically modify settings at a specific path
fn with_exclusive_settings_path<F, R>(path: &PathBuf, f: F) -> std::io::Result<R>
where
    F: FnOnce(&mut Value) -> R,
{
    crate::json_file::update_json(
        Path::new(path),
        crate::json_file::EmptyPolicy::EmptyObject,
        true,
        |settings| Ok(f(settings)),
    )
    .map(|outcome| outcome.result)
}

/// Add a permission rule to settings.json
/// Removes the pattern from other rule types first to prevent conflicts
pub fn add_rule(scope: Scope, pattern: &str, rule_type: RuleType) -> std::io::Result<()> {
    let formatted = format_pattern(pattern);

    with_exclusive_settings(scope, |settings| {
        // Ensure permissions object exists
        if settings.get("permissions").is_none() {
            settings["permissions"] = json!({});
        }

        let permissions = settings.get_mut("permissions").unwrap();

        // First, remove from ALL rule arrays to prevent conflicts
        // A pattern should only exist in one array at a time
        for other_type in ["allow", "ask", "deny"] {
            if let Some(arr) = permissions
                .get_mut(other_type)
                .and_then(|v| v.as_array_mut())
            {
                arr.retain(|r| r.as_str() != Some(&formatted));
            }
        }

        let rule_key = rule_type.as_str();

        // Ensure the rule array exists
        if permissions.get(rule_key).is_none() {
            permissions[rule_key] = json!([]);
        }

        let rules = permissions[rule_key].as_array_mut().unwrap();

        // Add the rule (we just removed any existing, so no need to check)
        rules.push(json!(formatted));
    })
}

/// Add a permission rule to a specific project's settings file
pub fn add_rule_to_project(
    scope: Scope,
    project_path: &str,
    pattern: &str,
    rule_type: RuleType,
) -> std::io::Result<()> {
    let formatted = format_pattern(pattern);
    let path = scope.path_for_project(project_path);

    with_exclusive_settings_path(&path, |settings| {
        // Ensure permissions object exists
        if settings.get("permissions").is_none() {
            settings["permissions"] = json!({});
        }

        let permissions = settings.get_mut("permissions").unwrap();

        // Remove from ALL rule arrays to prevent conflicts
        for other_type in ["allow", "ask", "deny"] {
            if let Some(arr) = permissions
                .get_mut(other_type)
                .and_then(|v| v.as_array_mut())
            {
                arr.retain(|r| r.as_str() != Some(&formatted));
            }
        }

        let rule_key = rule_type.as_str();

        // Ensure the rule array exists
        if permissions.get(rule_key).is_none() {
            permissions[rule_key] = json!([]);
        }

        let rules = permissions[rule_key].as_array_mut().unwrap();
        rules.push(json!(formatted));
    })
}

/// Remove a permission rule from a specific project's settings file.
/// Mirror of `add_rule_to_project` for undo: strips `pattern` from every rule
/// array (allow/ask/deny) at the project-scoped path.
pub fn remove_rule_from_project(
    scope: Scope,
    project_path: &str,
    pattern: &str,
) -> std::io::Result<bool> {
    let formatted = format_pattern(pattern);
    let path = scope.path_for_project(project_path);

    with_exclusive_settings_path(&path, |settings| {
        let Some(permissions) = settings.get_mut("permissions") else {
            return false;
        };

        let mut removed = false;
        for rule_type in ["allow", "ask", "deny"] {
            if let Some(arr) = permissions
                .get_mut(rule_type)
                .and_then(|v| v.as_array_mut())
            {
                let len_before = arr.len();
                arr.retain(|r| r.as_str() != Some(&formatted));
                if arr.len() < len_before {
                    removed = true;
                }
            }
        }
        removed
    })
}

/// Remove a permission rule from settings.json
pub fn remove_rule(scope: Scope, pattern: &str) -> std::io::Result<bool> {
    let formatted = format_pattern(pattern);

    with_exclusive_settings(scope, |settings| {
        let Some(permissions) = settings.get_mut("permissions") else {
            return false;
        };

        let mut removed = false;

        for rule_type in ["allow", "ask", "deny"] {
            if let Some(rules) = permissions.get_mut(rule_type)
                && let Some(arr) = rules.as_array_mut()
            {
                let len_before = arr.len();
                arr.retain(|r| r.as_str() != Some(&formatted));
                if arr.len() < len_before {
                    removed = true;
                }
            }
        }

        removed
    })
}

/// Pull the rule arrays out of a parsed settings object.
fn extract_rules(settings: &Value, scope: Scope) -> Vec<PermissionRule> {
    let mut rules = Vec::new();
    let Some(permissions) = settings.get("permissions") else {
        return rules;
    };
    for (rule_type, key) in [
        (RuleType::Allow, "allow"),
        (RuleType::Ask, "ask"),
        (RuleType::Deny, "deny"),
    ] {
        if let Some(arr) = permissions.get(key).and_then(|v| v.as_array()) {
            for pattern in arr {
                if let Some(p) = pattern.as_str() {
                    rules.push(PermissionRule {
                        pattern: p.to_string(),
                        rule_type,
                        scope,
                    });
                }
            }
        }
    }
    rules
}

/// Load settings from a specific path, returning an empty object if absent.
fn load_settings_path(path: &std::path::Path) -> Value {
    if !path.exists() {
        return json!({});
    }
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

/// List all permission rules from a scope (cwd-relative for project/local)
pub fn list_rules(scope: Scope) -> Vec<PermissionRule> {
    extract_rules(&load_settings(scope), scope)
}

/// List permission rules for a specific project directory (not cwd-relative).
pub fn list_rules_for_project(scope: Scope, project_path: &str) -> Vec<PermissionRule> {
    extract_rules(
        &load_settings_path(&scope.path_for_project(project_path)),
        scope,
    )
}

/// List all rules from all scopes
pub fn list_all_rules() -> Vec<PermissionRule> {
    let mut rules = Vec::new();
    for scope in [Scope::User, Scope::Project, Scope::Local] {
        rules.extend(list_rules(scope));
    }
    rules
}

/// Format a pattern for settings.json (add Bash() wrapper if needed)
pub fn format_pattern(pattern: &str) -> String {
    if pattern.starts_with("Bash(") && pattern.ends_with(')') {
        pattern.to_string()
    } else {
        format!("Bash({})", pattern)
    }
}

/// Parse a pattern from settings.json format
pub fn parse_pattern(formatted: &str) -> String {
    if formatted.starts_with("Bash(") && formatted.ends_with(')') {
        formatted[5..formatted.len() - 1].to_string()
    } else {
        formatted.to_string()
    }
}

/// Path to Antigravity's global settings file
/// (`~/.gemini/antigravity-cli/settings.json`), which holds the native
/// `permissions` lists. Distinct from the hooks file
/// (`~/.gemini/config/hooks.json`): settings live under `antigravity-cli/`.
///
/// These rules are read by agy's own permission engine, not by tool-gates.
/// `Settings::load` never reads this file: `tool-gates agy allowlist` writes a
/// broad `command(<prog>)` allow list here on the explicit understanding that
/// the hook still tightens over any dangerous form, so feeding it back in as a
/// tool-gates allow list would let `command(find)` approve `find . -delete`.
pub fn antigravity_settings_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".gemini")
        .join("antigravity-cli")
        .join("settings.json")
}

/// Format a pattern for Antigravity settings.json (wrap in command() if needed)
pub fn format_antigravity_pattern(pattern: &str) -> String {
    let p = pattern.trim();
    if (p.starts_with("command(") || p.starts_with("Bash(")) && p.ends_with(')') {
        if p.starts_with("Bash(") {
            format!("command({})", &p[5..p.len() - 1])
        } else {
            p.to_string()
        }
    } else {
        format!("command({})", p)
    }
}

/// Parse a pattern from Antigravity settings format (strip command(...) or Bash(...))
pub fn parse_antigravity_pattern(formatted: &str) -> String {
    let f = formatted.trim();
    if (f.starts_with("command(") || f.starts_with("Bash(")) && f.ends_with(')') {
        let start = if f.starts_with("command(") { 8 } else { 5 };
        f[start..f.len() - 1].to_string()
    } else {
        f.to_string()
    }
}

/// Add a permission rule to Antigravity settings.json
pub fn add_antigravity_rule(pattern: &str, rule_type: RuleType) -> std::io::Result<()> {
    let formatted = format_antigravity_pattern(pattern);
    let path = antigravity_settings_path();

    with_exclusive_settings_path(&path, |settings| {
        if settings.get("permissions").is_none() {
            settings["permissions"] = json!({});
        }

        let permissions = settings.get_mut("permissions").unwrap();

        for other_type in ["allow", "ask", "deny"] {
            if let Some(arr) = permissions
                .get_mut(other_type)
                .and_then(|v| v.as_array_mut())
            {
                arr.retain(|r| r.as_str() != Some(&formatted));
            }
        }

        let rule_key = rule_type.as_str();
        if permissions.get(rule_key).is_none() {
            permissions[rule_key] = json!([]);
        }

        let rules = permissions[rule_key].as_array_mut().unwrap();
        rules.push(json!(formatted));
    })
}

/// Remove a permission rule from Antigravity settings.json
pub fn remove_antigravity_rule(pattern: &str) -> std::io::Result<bool> {
    let formatted = format_antigravity_pattern(pattern);
    let raw = pattern.trim();
    let path = antigravity_settings_path();

    with_exclusive_settings_path(&path, |settings| {
        let Some(permissions) = settings.get_mut("permissions") else {
            return false;
        };

        let mut removed = false;
        for rule_type in ["allow", "ask", "deny"] {
            if let Some(rules) = permissions.get_mut(rule_type)
                && let Some(arr) = rules.as_array_mut()
            {
                let len_before = arr.len();
                arr.retain(|r| {
                    if let Some(s) = r.as_str() {
                        s != formatted && s != raw && parse_antigravity_pattern(s) != raw
                    } else {
                        true
                    }
                });
                if arr.len() < len_before {
                    removed = true;
                }
            }
        }
        removed
    })
}

/// List all permission rules from Antigravity settings.json
pub fn list_antigravity_rules() -> Vec<PermissionRule> {
    let path = antigravity_settings_path();
    let settings = load_settings_path(&path);
    extract_rules(&settings, Scope::User)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn with_temp_home<F>(test: F)
    where
        F: FnOnce(),
    {
        let saved_home = std::env::var("HOME").ok();
        let temp_dir = TempDir::new().unwrap();
        // SAFETY: Test runs serialized
        unsafe { std::env::set_var("HOME", temp_dir.path()) };
        test();
        if let Some(h) = saved_home {
            unsafe { std::env::set_var("HOME", h) };
        } else {
            unsafe { std::env::remove_var("HOME") };
        }
    }

    #[test]
    fn test_format_pattern() {
        assert_eq!(format_pattern("npm install:*"), "Bash(npm install:*)");
        assert_eq!(format_pattern("Bash(git*)"), "Bash(git*)");
    }

    #[test]
    fn test_parse_pattern() {
        assert_eq!(parse_pattern("Bash(npm install:*)"), "npm install:*");
        assert_eq!(parse_pattern("git*"), "git*");
    }

    #[test]
    fn test_format_antigravity_pattern() {
        assert_eq!(
            format_antigravity_pattern("cargo test"),
            "command(cargo test)"
        );
        assert_eq!(format_antigravity_pattern("command(git*)"), "command(git*)");
        assert_eq!(format_antigravity_pattern("Bash(npm:*)"), "command(npm:*)");
    }

    #[test]
    fn test_parse_antigravity_pattern() {
        assert_eq!(
            parse_antigravity_pattern("command(cargo test)"),
            "cargo test"
        );
        assert_eq!(parse_antigravity_pattern("Bash(npm:*)"), "npm:*");
        assert_eq!(parse_antigravity_pattern("cargo test"), "cargo test");
    }

    #[test]
    fn test_scope_from_str() {
        assert_eq!(Scope::parse("user"), Some(Scope::User));
        assert_eq!(Scope::parse("project"), Some(Scope::Project));
        assert_eq!(Scope::parse("local"), Some(Scope::Local));
        assert_eq!(Scope::parse("invalid"), None);
    }

    #[test]
    #[serial_test::serial]
    fn test_user_scope_respects_config_dir_env() {
        let temp_dir = TempDir::new().unwrap();
        let custom_path = temp_dir.path().to_string_lossy().to_string();

        // Set the env var
        unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", &custom_path) };

        let path = Scope::User.path();
        assert!(path.starts_with(temp_dir.path()));
        assert!(path.ends_with("settings.json"));

        // Clean up
        unsafe { std::env::remove_var("CLAUDE_CONFIG_DIR") };
    }

    #[test]
    #[serial_test::serial]
    fn add_rule_round_trips_to_user_settings() {
        let temp = TempDir::new().unwrap();
        // SAFETY: serialized with other env-mutating tests via serial.
        unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", temp.path()) };

        add_rule(Scope::User, "git status:*", RuleType::Allow).unwrap();

        let path = temp.path().join("settings.json");
        let v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let allow = v["permissions"]["allow"].as_array().unwrap();
        assert!(allow.iter().any(|r| r == "Bash(git status:*)"));

        unsafe { std::env::remove_var("CLAUDE_CONFIG_DIR") };
    }

    #[test]
    #[serial_test::serial]
    fn add_rule_preserves_unrelated_config_and_dedups_across_types() {
        let temp = TempDir::new().unwrap();
        unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", temp.path()) };
        let path = temp.path().join("settings.json");

        // Seed a valid file with an unrelated key and the pattern already in ask.
        let original = r#"{"env":{"FOO":"bar"},"permissions":{"ask":["Bash(deploy:*)"]}}"#;
        fs::write(&path, original).unwrap();

        add_rule(Scope::User, "deploy:*", RuleType::Allow).unwrap();

        let v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["env"]["FOO"], "bar"); // unrelated config preserved
        let ask = v["permissions"]["ask"].as_array().unwrap();
        assert!(!ask.iter().any(|r| r == "Bash(deploy:*)")); // moved out of ask
        let allow = v["permissions"]["allow"].as_array().unwrap();
        assert!(allow.iter().any(|r| r == "Bash(deploy:*)")); // into allow

        let backups = fs::read_dir(temp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("settings.json.backup-")
            })
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1, "one pre-update backup must be retained");
        assert_eq!(fs::read_to_string(backups[0].path()).unwrap(), original);

        unsafe { std::env::remove_var("CLAUDE_CONFIG_DIR") };
    }

    #[test]
    #[serial_test::serial]
    fn add_rule_does_not_wipe_an_unparseable_settings_file() {
        let temp = TempDir::new().unwrap();
        unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", temp.path()) };
        let path = temp.path().join("settings.json");

        // A settings file the user hand-edited into an invalid state.
        let original = "{ \"permissions\": { \"allow\": [ } broken";
        fs::write(&path, original).unwrap();

        // Must fail closed, leaving the original bytes intact.
        let result = add_rule(Scope::User, "git status:*", RuleType::Allow);
        assert!(
            result.is_err(),
            "an invalid settings.json must not be silently overwritten"
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            original,
            "the original (invalid) file must be preserved on failure"
        );

        unsafe { std::env::remove_var("CLAUDE_CONFIG_DIR") };
    }

    #[test]
    #[serial_test::serial]
    fn add_rule_creates_a_fresh_settings_file_when_absent() {
        let temp = TempDir::new().unwrap();
        unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", temp.path()) };

        // No settings.json exists yet.
        add_rule(Scope::User, "ls:*", RuleType::Allow).unwrap();

        let path = temp.path().join("settings.json");
        assert!(path.exists());
        let v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(
            v["permissions"]["allow"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "Bash(ls:*)")
        );

        unsafe { std::env::remove_var("CLAUDE_CONFIG_DIR") };
    }

    #[test]
    #[serial_test::serial]
    fn antigravity_rule_add_and_remove_round_trip() {
        with_temp_home(|| {
            let agy_dir = dirs::home_dir()
                .unwrap()
                .join(".gemini")
                .join("antigravity-cli");
            fs::create_dir_all(&agy_dir).unwrap();

            // Add allow rule
            add_antigravity_rule("cargo test", RuleType::Allow).unwrap();

            let rules = list_antigravity_rules();
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].pattern, "command(cargo test)");
            assert_eq!(rules[0].rule_type, RuleType::Allow);

            // Add deny rule for same pattern - should move from allow to deny
            add_antigravity_rule("cargo test", RuleType::Deny).unwrap();
            let rules = list_antigravity_rules();
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].rule_type, RuleType::Deny);

            // Remove rule
            let removed = remove_antigravity_rule("cargo test").unwrap();
            assert!(removed);
            let rules = list_antigravity_rules();
            assert!(rules.is_empty());
        });
    }
}

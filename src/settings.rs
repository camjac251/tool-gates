//! Settings.json parsing and matching for Claude Code permissions.
//!
//! Loads user (~/.claude/settings.json) and project (.claude/settings.json)
//! settings to check if a command matches any allow/deny/ask rules.

use serde::Deserialize;
use std::borrow::Cow;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Normalize a path by resolving `.` and `..` components without requiring the path to exist.
fn normalize_path(path: &Path) -> String {
    let mut components: Vec<Component> = Vec::new();

    for component in path.components() {
        match component {
            Component::CurDir => {
                // Skip `.` (current directory)
            }
            Component::ParentDir => {
                // Pop the last normal component if possible
                if let Some(Component::Normal(_)) = components.last() {
                    components.pop();
                } else {
                    // Keep the `..` if we can't go up further
                    components.push(component);
                }
            }
            _ => {
                components.push(component);
            }
        }
    }

    let normalized: PathBuf = components.iter().collect();
    normalized.to_string_lossy().to_string()
}

#[derive(Debug, Deserialize, Default)]
pub struct Permissions {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
    #[serde(default, rename = "additionalDirectories")]
    pub additional_directories: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Settings {
    #[serde(default)]
    pub permissions: Permissions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsDecision {
    Allow,
    Deny,
    Ask,
    NoMatch,
}

impl Settings {
    /// Load and merge settings from all locations.
    ///
    /// Settings precedence (highest to lowest):
    /// 1. Managed settings (`/etc/claude-code/managed-settings.json` on Linux)
    /// 2. Local project settings (`.claude/settings.local.json`)
    /// 3. Shared project settings (`.claude/settings.json`)
    /// 4. User settings (`~/.claude/settings.json`)
    ///
    /// We load in reverse order and merge, so higher priority settings override.
    pub fn load(cwd: &str) -> Self {
        let mut merged = Settings::default();

        // 4. User settings (~/.claude/settings.json) - lowest priority
        // Check CLAUDE_CONFIG_DIR env var first, fall back to ~/.claude
        let user_config_dir = std::env::var("CLAUDE_CONFIG_DIR")
            .map(PathBuf::from)
            .ok()
            .or_else(|| dirs::home_dir().map(|h| h.join(".claude")));
        if let Some(config_dir) = user_config_dir {
            let user_path = config_dir.join("settings.json");
            if let Ok(s) = Self::load_file(&user_path) {
                merged.merge(s);
            }
        }

        // 3. Shared project settings (.claude/settings.json)
        if !cwd.is_empty() {
            let project_path = Path::new(cwd).join(".claude/settings.json");
            if let Ok(s) = Self::load_file(&project_path) {
                merged.merge(s);
            }
        }

        // 2. Local project settings (.claude/settings.local.json)
        if !cwd.is_empty() {
            let local_path = Path::new(cwd).join(".claude/settings.local.json");
            if let Ok(s) = Self::load_file(&local_path) {
                merged.merge(s);
            }
        }

        // 1. Enterprise managed settings - highest priority
        #[cfg(target_os = "linux")]
        {
            let managed_path = Path::new("/etc/claude-code/managed-settings.json");
            if let Ok(s) = Self::load_file(managed_path) {
                merged.merge(s);
            }
        }
        #[cfg(target_os = "macos")]
        {
            let managed_path =
                Path::new("/Library/Application Support/ClaudeCode/managed-settings.json");
            if let Ok(s) = Self::load_file(managed_path) {
                merged.merge(s);
            }
        }

        merged
    }

    fn load_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let settings: Settings = serde_json::from_str(&content)?;
        Ok(settings)
    }

    fn merge(&mut self, other: Settings) {
        self.permissions.allow.extend(other.permissions.allow);
        self.permissions.deny.extend(other.permissions.deny);
        self.permissions.ask.extend(other.permissions.ask);
        self.permissions
            .additional_directories
            .extend(other.permissions.additional_directories);
    }

    /// Get all allowed directories (cwd + additionalDirectories from settings).
    /// Expands ~ to home directory and resolves relative paths against cwd.
    pub fn allowed_directories(&self, cwd: &str) -> Vec<String> {
        let mut dirs = vec![cwd.to_string()];
        let cwd_path = Path::new(cwd);

        for dir in &self.permissions.additional_directories {
            let expanded = if let Some(suffix) = dir.strip_prefix("~/") {
                // Expand ~ to home directory
                if let Some(home) = dirs::home_dir() {
                    home.join(suffix).to_string_lossy().to_string()
                } else {
                    dir.clone()
                }
            } else if dir == "~" {
                // Expand standalone ~
                if let Some(home) = dirs::home_dir() {
                    home.to_string_lossy().to_string()
                } else {
                    dir.clone()
                }
            } else if dir.starts_with('/') {
                // Absolute path - use as-is
                dir.clone()
            } else {
                // Relative path (./foo, ../bar, or just "foo") - resolve against cwd
                let joined = cwd_path.join(dir);
                // Normalize the path (resolve . and ..)
                normalize_path(&joined)
            };
            dirs.push(expanded);
        }
        dirs
    }

    /// Check if command matches any deny rules.
    pub fn is_denied(&self, command: &str) -> bool {
        self.matches_any(&self.permissions.deny, command)
    }

    /// Check command against settings rules.
    /// Priority: deny first, then most-specific pattern wins between ask/allow (ties go to ask).
    pub fn check_command(&self, command: &str) -> SettingsDecision {
        if self.matches_any(&self.permissions.deny, command) {
            return SettingsDecision::Deny;
        }
        self.resolve_ask_allow(command)
    }

    /// Check command against settings rules, excluding deny (for use after deny check).
    /// Most-specific pattern wins between ask and allow (ties go to ask).
    pub fn check_command_excluding_deny(&self, command: &str) -> SettingsDecision {
        self.resolve_ask_allow(command)
    }

    /// Match command against Bash(...) patterns
    fn matches_any(&self, patterns: &[String], command: &str) -> bool {
        for pattern in patterns {
            if let Some(bash_pattern) = pattern.strip_prefix("Bash(") {
                if let Some(inner) = bash_pattern.strip_suffix(')') {
                    if Self::matches_bash_pattern(inner, command) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if an MCP tool is allowed in settings.json.
    ///
    /// MCP permissions use the format:
    /// - `mcp__<server>` - entire server allowed
    /// - `mcp__<server>__<tool>` - specific tool allowed
    /// - `mcp__<server>__*` - server with wildcard
    ///
    /// Returns: Allow, Deny, Ask, or NoMatch
    pub fn check_mcp_tool(&self, server: &str, tool: &str) -> SettingsDecision {
        // Check deny rules first
        if self.matches_mcp_pattern(&self.permissions.deny, server, tool) {
            return SettingsDecision::Deny;
        }

        // Check ask rules
        if self.matches_mcp_pattern(&self.permissions.ask, server, tool) {
            return SettingsDecision::Ask;
        }

        // Check allow rules
        if self.matches_mcp_pattern(&self.permissions.allow, server, tool) {
            return SettingsDecision::Allow;
        }

        SettingsDecision::NoMatch
    }

    /// Check if an MCP server/tool matches any mcp__ patterns in the list.
    fn matches_mcp_pattern(&self, patterns: &[String], server: &str, tool: &str) -> bool {
        for pattern in patterns {
            // Check for mcp__ prefix
            if let Some(mcp_pattern) = pattern.strip_prefix("mcp__") {
                // mcp__server - entire server
                if mcp_pattern == server {
                    return true;
                }

                // mcp__server__tool - specific tool
                let specific = format!("{}__{}", server, tool);
                if mcp_pattern == specific {
                    return true;
                }

                // mcp__server__* - wildcard for server
                let wildcard = format!("{}__*", server);
                if mcp_pattern == wildcard {
                    return true;
                }
            }
        }
        false
    }

    /// Match Bash pattern:
    /// - "cmd:*" - prefix match with word boundary (git:* matches "git status")
    /// - "cmd*" - glob prefix match (cat /dev/zero* matches "cat /dev/zero | head")
    /// - "cmd" - exact match
    fn matches_bash_pattern(pattern: &str, command: &str) -> bool {
        let expanded = Self::expand_pattern(pattern);
        let pattern = expanded.as_ref();

        if let Some(prefix) = pattern.strip_suffix(":*") {
            command == prefix || command.starts_with(&format!("{prefix} "))
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            command.starts_with(prefix)
        } else {
            command == pattern
        }
    }

    /// Expand `~`, `$HOME`, `${HOME}`, `$USER`, `${USER}` in a pattern to
    /// their concrete values, so settings.json rules written with any
    /// of these forms match real commands.
    ///
    /// Uses the lossy variant: if a recognized variable can't be resolved,
    /// the pattern is left unchanged. A non-matching pattern is the safe
    /// side for deny rules (they simply won't match rather than crash),
    /// and for allow rules the conservative default is "no match" which
    /// preserves today's behavior.
    fn expand_pattern(pattern: &str) -> Cow<'_, str> {
        if !pattern.contains('$') && !pattern.contains('~') {
            return Cow::Borrowed(pattern);
        }
        let expanded = crate::gates::helpers::expand_path_vars_lossy(pattern);
        if expanded == pattern {
            Cow::Borrowed(pattern)
        } else {
            Cow::Owned(expanded)
        }
    }

    /// Specificity score for a pattern match. Higher = more specific.
    /// Exact matches get usize::MAX. Prefix matches get the prefix length.
    fn pattern_specificity(pattern: &str, command: &str) -> Option<usize> {
        let expanded = Self::expand_pattern(pattern);
        let pattern = expanded.as_ref();

        if let Some(prefix) = pattern.strip_suffix(":*") {
            if command == prefix || command.starts_with(&format!("{prefix} ")) {
                Some(prefix.len())
            } else {
                None
            }
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            if command.starts_with(prefix) {
                Some(prefix.len())
            } else {
                None
            }
        } else if command == pattern {
            Some(usize::MAX)
        } else {
            None
        }
    }

    /// Highest specificity score among all matching Bash patterns in the list.
    fn best_match_specificity(patterns: &[String], command: &str) -> Option<usize> {
        let mut best: Option<usize> = None;
        for pattern in patterns {
            if let Some(bash_pattern) = pattern.strip_prefix("Bash(") {
                if let Some(inner) = bash_pattern.strip_suffix(')') {
                    if let Some(score) = Self::pattern_specificity(inner, command) {
                        best = Some(best.map_or(score, |b| b.max(score)));
                    }
                }
            }
        }
        best
    }

    /// Resolve between ask and allow using pattern specificity.
    /// More specific pattern wins; ties go to ask (safer default).
    fn resolve_ask_allow(&self, command: &str) -> SettingsDecision {
        let ask_score = Self::best_match_specificity(&self.permissions.ask, command);
        let allow_score = Self::best_match_specificity(&self.permissions.allow, command);

        match (ask_score, allow_score) {
            (Some(a), Some(b)) if b > a => SettingsDecision::Allow,
            (Some(_), _) => SettingsDecision::Ask,
            (_, Some(_)) => SettingsDecision::Allow,
            _ => SettingsDecision::NoMatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_match() {
        assert!(Settings::matches_bash_pattern("git:*", "git"));
        assert!(Settings::matches_bash_pattern("git:*", "git status"));
        assert!(Settings::matches_bash_pattern(
            "git:*",
            "git push origin main"
        ));
        assert!(!Settings::matches_bash_pattern("git:*", "gitk"));
        assert!(!Settings::matches_bash_pattern("git:*", "github"));
    }

    #[test]
    fn test_exact_match() {
        assert!(Settings::matches_bash_pattern("pwd", "pwd"));
        assert!(!Settings::matches_bash_pattern("pwd", "pwd -L"));
        assert!(!Settings::matches_bash_pattern("pwd", "pwdx"));
    }

    #[test]
    fn test_glob_match() {
        // Glob suffix: "cat /dev/zero*" matches anything starting with "cat /dev/zero"
        assert!(Settings::matches_bash_pattern(
            "cat /dev/zero*",
            "cat /dev/zero"
        ));
        assert!(Settings::matches_bash_pattern(
            "cat /dev/zero*",
            "cat /dev/zero | head"
        ));
        assert!(!Settings::matches_bash_pattern(
            "cat /dev/zero*",
            "cat /dev/random"
        ));
        assert!(!Settings::matches_bash_pattern(
            "cat /dev/zero*",
            "cat file.txt"
        ));
    }

    #[test]
    fn test_exact_match_with_args() {
        assert!(Settings::matches_bash_pattern("rm -rf /", "rm -rf /"));
        assert!(!Settings::matches_bash_pattern("rm -rf /", "rm -rf /tmp"));
    }

    #[test]
    fn test_check_command_priority() {
        let settings = Settings {
            permissions: Permissions {
                deny: vec!["Bash(rm -rf /)".to_string()],
                ask: vec!["Bash(rm:*)".to_string()],
                allow: vec!["Bash(ls:*)".to_string()],
                additional_directories: vec![],
            },
        };

        // Deny wins
        assert_eq!(settings.check_command("rm -rf /"), SettingsDecision::Deny);
        // Ask for other rm commands
        assert_eq!(settings.check_command("rm file.txt"), SettingsDecision::Ask);
        // Allow for ls
        assert_eq!(settings.check_command("ls -la"), SettingsDecision::Allow);
        // No match for unknown
        assert_eq!(settings.check_command("foo"), SettingsDecision::NoMatch);
    }

    #[test]
    fn test_cat_dev_zero_deny() {
        let settings = Settings {
            permissions: Permissions {
                deny: vec!["Bash(cat /dev/zero*)".to_string()], // glob pattern
                ask: vec![],
                allow: vec!["Bash(cat:*)".to_string()],
                additional_directories: vec![],
            },
        };

        // Deny wins over allow for /dev/zero
        assert_eq!(
            settings.check_command("cat /dev/zero"),
            SettingsDecision::Deny
        );
        // But regular cat is allowed
        assert_eq!(
            settings.check_command("cat file.txt"),
            SettingsDecision::Allow
        );
    }

    #[test]
    fn test_normalize_path() {
        use std::path::Path;

        // Basic normalization
        assert_eq!(normalize_path(Path::new("/a/b/c")), "/a/b/c");
        assert_eq!(normalize_path(Path::new("/a/./b/c")), "/a/b/c");
        assert_eq!(normalize_path(Path::new("/a/b/../c")), "/a/c");
        assert_eq!(normalize_path(Path::new("/a/b/c/..")), "/a/b");
        assert_eq!(normalize_path(Path::new("/a/b/./c/../d")), "/a/b/d");

        // Multiple .. components
        assert_eq!(normalize_path(Path::new("/a/b/c/../../d")), "/a/d");

        // Leading .. preserved when can't go higher
        assert_eq!(normalize_path(Path::new("../a/b")), "../a/b");
    }

    #[test]
    fn test_allowed_directories_relative_paths() {
        let settings = Settings {
            permissions: Permissions {
                additional_directories: vec![
                    "./subprojects".to_string(),
                    "../sibling-repo".to_string(),
                    "bare-subdir".to_string(),
                ],
                ..Default::default()
            },
        };

        let dirs = settings.allowed_directories("/home/user/project");

        // cwd is always first
        assert_eq!(dirs[0], "/home/user/project");

        // ./subprojects resolved against cwd
        assert_eq!(dirs[1], "/home/user/project/subprojects");

        // ../sibling-repo resolved against cwd
        assert_eq!(dirs[2], "/home/user/sibling-repo");

        // bare-subdir resolved against cwd
        assert_eq!(dirs[3], "/home/user/project/bare-subdir");
    }

    #[test]
    fn test_allowed_directories_absolute_paths() {
        let settings = Settings {
            permissions: Permissions {
                additional_directories: vec!["/absolute/path".to_string()],
                ..Default::default()
            },
        };

        let dirs = settings.allowed_directories("/home/user/project");

        // Absolute paths unchanged
        assert_eq!(dirs[1], "/absolute/path");
    }

    #[test]
    fn test_allowed_directories_tilde_expansion() {
        let settings = Settings {
            permissions: Permissions {
                additional_directories: vec!["~/other-project".to_string(), "~".to_string()],
                ..Default::default()
            },
        };

        let dirs = settings.allowed_directories("/home/user/project");

        // Tilde should be expanded (we can't assert exact value, but it shouldn't start with ~)
        assert!(
            !dirs[1].starts_with('~'),
            "~/other-project should be expanded"
        );
        assert!(!dirs[2].starts_with('~'), "~ should be expanded");

        // Should end with the suffix
        assert!(dirs[1].ends_with("other-project"));
    }

    #[test]
    fn test_allowed_directories_mixed() {
        let settings = Settings {
            permissions: Permissions {
                additional_directories: vec![
                    "./relative".to_string(),
                    "/absolute".to_string(),
                    "~/home-relative".to_string(),
                ],
                ..Default::default()
            },
        };

        let dirs = settings.allowed_directories("/project");

        assert_eq!(dirs.len(), 4); // cwd + 3 additional
        assert_eq!(dirs[0], "/project");
        assert_eq!(dirs[1], "/project/relative");
        assert_eq!(dirs[2], "/absolute");
        assert!(!dirs[3].starts_with('~'));
    }

    // === MCP Permission Tests ===

    #[test]
    fn test_mcp_server_allow() {
        // mcp__server-a allows entire server
        let settings = Settings {
            permissions: Permissions {
                allow: vec!["mcp__server-a".to_string()],
                ..Default::default()
            },
        };

        assert_eq!(
            settings.check_mcp_tool("server-a", "tool_one"),
            SettingsDecision::Allow
        );
        assert_eq!(
            settings.check_mcp_tool("server-a", "tool_two"),
            SettingsDecision::Allow
        );
        // Different server - no match
        assert_eq!(
            settings.check_mcp_tool("server-b", "tool_one"),
            SettingsDecision::NoMatch
        );
    }

    #[test]
    fn test_mcp_specific_tool_allow() {
        // mcp__server-a__tool_one allows only that tool
        let settings = Settings {
            permissions: Permissions {
                allow: vec!["mcp__server-a__tool_one".to_string()],
                ..Default::default()
            },
        };

        assert_eq!(
            settings.check_mcp_tool("server-a", "tool_one"),
            SettingsDecision::Allow
        );
        // Different tool on same server - no match
        assert_eq!(
            settings.check_mcp_tool("server-a", "tool_two"),
            SettingsDecision::NoMatch
        );
    }

    #[test]
    fn test_mcp_wildcard_allow() {
        // mcp__server-a__* allows all tools on server-a
        let settings = Settings {
            permissions: Permissions {
                allow: vec!["mcp__server-a__*".to_string()],
                ..Default::default()
            },
        };

        assert_eq!(
            settings.check_mcp_tool("server-a", "tool_one"),
            SettingsDecision::Allow
        );
        assert_eq!(
            settings.check_mcp_tool("server-a", "tool_two"),
            SettingsDecision::Allow
        );
        // Different server - no match
        assert_eq!(
            settings.check_mcp_tool("server-b", "tool_one"),
            SettingsDecision::NoMatch
        );
    }

    #[test]
    fn test_mcp_deny_priority() {
        // Deny takes priority over allow
        let settings = Settings {
            permissions: Permissions {
                allow: vec!["mcp__server-a".to_string()],
                deny: vec!["mcp__server-a__dangerous_tool".to_string()],
                ..Default::default()
            },
        };

        // Specific tool is denied
        assert_eq!(
            settings.check_mcp_tool("server-a", "dangerous_tool"),
            SettingsDecision::Deny
        );
        // Other tools on server are allowed
        assert_eq!(
            settings.check_mcp_tool("server-a", "safe_tool"),
            SettingsDecision::Allow
        );
    }

    #[test]
    fn test_mcp_ask_priority() {
        // Ask takes priority over allow, but not deny
        let settings = Settings {
            permissions: Permissions {
                allow: vec!["mcp__server-a".to_string()],
                ask: vec!["mcp__server-a__risky_tool".to_string()],
                ..Default::default()
            },
        };

        // Specific tool requires asking
        assert_eq!(
            settings.check_mcp_tool("server-a", "risky_tool"),
            SettingsDecision::Ask
        );
        // Other tools on server are allowed
        assert_eq!(
            settings.check_mcp_tool("server-a", "safe_tool"),
            SettingsDecision::Allow
        );
    }

    #[test]
    fn test_mcp_no_match() {
        // Empty settings - no match
        let settings = Settings::default();

        assert_eq!(
            settings.check_mcp_tool("any-server", "any_tool"),
            SettingsDecision::NoMatch
        );
    }

    // === Specificity Tests (Bug 1: ask always beat allow) ===

    #[test]
    fn test_specific_allow_beats_broad_ask() {
        let settings = Settings {
            permissions: Permissions {
                ask: vec!["Bash(mytool:*)".to_string()],
                allow: vec!["Bash(mytool --config production:*)".to_string()],
                ..Default::default()
            },
        };

        // Specific allow ("mytool --config production" len=25) beats broad ask ("mytool" len=6)
        assert_eq!(
            settings.check_command("mytool --config production deploy"),
            SettingsDecision::Allow
        );
        // Other mytool commands still ask
        assert_eq!(
            settings.check_command("mytool run-dangerous"),
            SettingsDecision::Ask
        );
    }

    #[test]
    fn test_equal_specificity_ask_wins() {
        let settings = Settings {
            permissions: Permissions {
                ask: vec!["Bash(git push:*)".to_string()],
                allow: vec!["Bash(git push:*)".to_string()],
                ..Default::default()
            },
        };

        // Equal specificity: ask wins (safer default)
        assert_eq!(
            settings.check_command("git push origin main"),
            SettingsDecision::Ask
        );
    }

    #[test]
    fn test_exact_allow_beats_prefix_ask() {
        let settings = Settings {
            permissions: Permissions {
                ask: vec!["Bash(cargo:*)".to_string()],
                allow: vec!["Bash(cargo test)".to_string()],
                ..Default::default()
            },
        };

        // Exact match (usize::MAX) beats prefix match (5)
        assert_eq!(
            settings.check_command("cargo test"),
            SettingsDecision::Allow
        );
        // Other cargo commands still ask
        assert_eq!(
            settings.check_command("cargo publish"),
            SettingsDecision::Ask
        );
    }

    #[test]
    fn test_deny_still_wins_over_specific_allow() {
        let settings = Settings {
            permissions: Permissions {
                deny: vec!["Bash(rm -rf /)".to_string()],
                allow: vec!["Bash(rm -rf /)".to_string()],
                ..Default::default()
            },
        };

        assert_eq!(settings.check_command("rm -rf /"), SettingsDecision::Deny);
    }

    #[test]
    fn test_excluding_deny_uses_specificity() {
        let settings = Settings {
            permissions: Permissions {
                ask: vec!["Bash(mytool:*)".to_string()],
                allow: vec!["Bash(mytool --config production:*)".to_string()],
                ..Default::default()
            },
        };

        assert_eq!(
            settings.check_command_excluding_deny("mytool --config production deploy"),
            SettingsDecision::Allow
        );
        assert_eq!(
            settings.check_command_excluding_deny("mytool other"),
            SettingsDecision::Ask
        );
    }

    // === $HOME Expansion Tests (Bug 2) ===

    #[test]
    fn test_home_expansion_in_allow_pattern() {
        let home = dirs::home_dir().expect("HOME must be set for this test");
        let home_str = home.to_string_lossy();

        let settings = Settings {
            permissions: Permissions {
                allow: vec!["Bash(mytool run $HOME/scripts/deploy/*)".to_string()],
                ..Default::default()
            },
        };

        let cmd = format!("mytool run {home_str}/scripts/deploy/prod.sh --dry-run");
        assert_eq!(settings.check_command(&cmd), SettingsDecision::Allow);
    }

    #[test]
    fn test_home_expansion_in_deny_pattern() {
        let home = dirs::home_dir().expect("HOME must be set for this test");
        let home_str = home.to_string_lossy();

        let settings = Settings {
            permissions: Permissions {
                deny: vec!["Bash(rm $HOME/.ssh/*)".to_string()],
                ..Default::default()
            },
        };

        let cmd = format!("rm {home_str}/.ssh/id_rsa");
        assert_eq!(settings.check_command(&cmd), SettingsDecision::Deny);
    }

    #[test]
    fn test_home_expansion_with_specificity() {
        let home = dirs::home_dir().expect("HOME must be set for this test");
        let home_str = home.to_string_lossy();

        let settings = Settings {
            permissions: Permissions {
                ask: vec!["Bash(mytool run:*)".to_string()],
                allow: vec!["Bash(mytool run $HOME/scripts/trusted/*)".to_string()],
                ..Default::default()
            },
        };

        // Expanded allow pattern is more specific than "mytool run"
        let cmd = format!("mytool run {home_str}/scripts/trusted/deploy.sh --env staging");
        assert_eq!(settings.check_command(&cmd), SettingsDecision::Allow);

        // Other mytool run commands still ask
        assert_eq!(
            settings.check_command("mytool run untrusted.sh"),
            SettingsDecision::Ask
        );
    }

    #[test]
    fn test_no_home_no_crash() {
        // Pattern with $HOME when HOME can't be resolved still works (no match, no crash)
        assert!(!Settings::matches_bash_pattern(
            "$HOME/bin/tool",
            "/usr/bin/tool"
        ));
    }

    #[test]
    fn test_braced_home_expansion_in_deny_pattern() {
        let home = dirs::home_dir().expect("HOME must be set for this test");
        let home_str = home.to_string_lossy();

        let settings = Settings {
            permissions: Permissions {
                deny: vec!["Bash(rm ${HOME}/.ssh/*)".to_string()],
                ..Default::default()
            },
        };

        let cmd = format!("rm {home_str}/.ssh/id_rsa");
        assert_eq!(settings.check_command(&cmd), SettingsDecision::Deny);
    }

    #[test]
    fn test_dollar_user_expansion_in_deny_pattern() {
        let home = dirs::home_dir().expect("HOME must be set for this test");
        let home_str = home.to_string_lossy();

        let settings = Settings {
            permissions: Permissions {
                deny: vec!["Bash(rm /home/$USER/.ssh/*)".to_string()],
                ..Default::default()
            },
        };

        let cmd = format!("rm {home_str}/.ssh/id_rsa");
        assert_eq!(settings.check_command(&cmd), SettingsDecision::Deny);
    }

    #[test]
    fn test_tilde_expansion_in_allow_pattern() {
        let home = dirs::home_dir().expect("HOME must be set for this test");
        let home_str = home.to_string_lossy();

        let settings = Settings {
            permissions: Permissions {
                allow: vec!["Bash(mytool run ~/scripts/*)".to_string()],
                ..Default::default()
            },
        };

        let cmd = format!("mytool run {home_str}/scripts/deploy.sh");
        assert_eq!(settings.check_command(&cmd), SettingsDecision::Allow);
    }

    #[test]
    fn test_pattern_specificity_scores() {
        // Word-boundary: prefix length
        assert_eq!(
            Settings::pattern_specificity("git:*", "git status"),
            Some(3)
        );
        // Glob: prefix length
        assert_eq!(
            Settings::pattern_specificity("git push *", "git push origin"),
            Some(9)
        );
        // Exact: usize::MAX
        assert_eq!(
            Settings::pattern_specificity("pwd", "pwd"),
            Some(usize::MAX)
        );
        // No match
        assert_eq!(Settings::pattern_specificity("git:*", "cargo build"), None);
    }
}

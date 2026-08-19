//! Settings.json parsing and matching for Claude Code permissions.
//!
//! Loads user (~/.claude/settings.json) and project (.claude/settings.json)
//! settings to check if a command matches any allow/deny/ask rules.
//!
//! Which of those scopes participate is a per-client decision: see
//! [`Settings::resolve`] for the enterprise managed-only branch.

use serde::Deserialize;
use std::borrow::Cow;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::models::Client;

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

/// Strip the `Bash(...)` or `command(...)` wrapper around a shell pattern.
///
/// `command(...)` is Antigravity's spelling of the same rule. Accepting it here
/// means a rule copied out of an agy settings file keeps working when it is
/// written into `.claude/settings.json`, which is where tool-gates reads rules
/// from for every client.
pub(crate) fn strip_command_pattern(pattern: &str) -> Option<&str> {
    if let Some(rest) = pattern.strip_prefix("Bash(") {
        rest.strip_suffix(')')
    } else if let Some(rest) = pattern.strip_prefix("command(") {
        rest.strip_suffix(')')
    } else {
        None
    }
}

/// Match a file path against a gitignore-style glob from a Claude settings.json
/// file rule (the `...` inside `Write(...)` / `Edit(...)`).
///
/// Semantics (a practical subset of Claude Code's matcher):
/// - `**` matches any number of path segments (including `/`)
/// - a leading `**/` also matches zero segments, so `**/.env*` matches `.env`
/// - `*` matches within a single segment (never `/`)
/// - `?` matches a single non-`/` char
/// - a pattern with no `/` is treated as `**/<pattern>` (matches at any depth),
///   mirroring gitignore's basename rule (`*.min.js` matches `a/b/c.min.js`)
fn path_matches_glob(pattern: &str, path: &str) -> bool {
    let effective: Cow<str> = if pattern.contains('/') {
        Cow::Borrowed(pattern)
    } else {
        Cow::Owned(format!("**/{pattern}"))
    };
    match glob_to_regex(&effective) {
        Some(re) => re.is_match(path),
        // A pattern we can't compile simply never matches. The glob grammar is
        // small and patterns are user-authored, so an uncompilable pattern is a
        // typo, not a boundary we silently drop.
        None => false,
    }
}

/// Compile a path glob into an anchored regex. Returns `None` if the resulting
/// regex cannot be compiled (treated as "no match" by the caller).
fn glob_to_regex(pattern: &str) -> Option<regex::Regex> {
    let mut re = String::with_capacity(pattern.len() * 2 + 2);
    re.push('^');
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => {
                if chars.peek() == Some(&'*') {
                    chars.next(); // consume the second '*'
                    if chars.peek() == Some(&'/') {
                        chars.next(); // consume the '/'
                        // `**/` matches zero or more leading path segments
                        re.push_str("(?:.*/)?");
                    } else {
                        re.push_str(".*");
                    }
                } else {
                    re.push_str("[^/]*");
                }
            }
            '?' => re.push_str("[^/]"),
            '/' => re.push('/'),
            other => {
                let mut buf = [0u8; 4];
                re.push_str(&regex::escape(other.encode_utf8(&mut buf)));
            }
        }
    }
    re.push('$');
    regex::Regex::new(&re).ok()
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

/// The enterprise managed settings document.
///
/// Parsed apart from the lower scopes for two reasons: it is the only document
/// whose `allowManagedPermissionRulesOnly` value has authority, and a malformed
/// `permissions` block in it must not fall back to lower scopes.
#[derive(Debug, Default)]
pub struct ManagedSettings {
    /// Top-level `allowManagedPermissionRulesOnly`, honored as a boolean only.
    /// When true, Claude's permission set is this document and nothing else.
    pub permission_rules_only: bool,
    pub permissions: Permissions,
}

impl ManagedSettings {
    /// Parse a managed document. Returns `None` when the content is not valid
    /// JSON, which keeps the managed scope out of resolution entirely.
    ///
    /// A document that is valid JSON but carries a malformed `permissions`
    /// block yields an empty permission set rather than an error. The flag is
    /// still authoritative there, and recovering by merging lower scopes would
    /// hand the invocation exactly the grants the flag exists to withhold.
    pub fn parse(content: &str) -> Option<Self> {
        let root: serde_json::Value = serde_json::from_str(content).ok()?;
        Some(Self {
            permission_rules_only: root
                .get("allowManagedPermissionRulesOnly")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            permissions: root
                .get("permissions")
                .and_then(|value| serde_json::from_value::<Permissions>(value.clone()).ok())
                .unwrap_or_default(),
        })
    }
}

/// Enterprise managed settings location for the host platform.
fn platform_managed_path() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Some(PathBuf::from("/etc/claude-code/managed-settings.json"))
    }
    #[cfg(target_os = "macos")]
    {
        Some(PathBuf::from(
            "/Library/Application Support/ClaudeCode/managed-settings.json",
        ))
    }
    #[cfg(target_os = "windows")]
    {
        Some(PathBuf::from(
            "C:\\Program Files\\ClaudeCode\\managed-settings.json",
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Host locations the settings loader reads. Project and local documents are
/// always derived from the invocation `cwd`, so only the two machine-global
/// scopes appear here.
#[derive(Debug, Clone, Default)]
pub struct SettingsPaths {
    /// Directory holding the user document, which is `settings.json` inside it.
    pub user_config_dir: Option<PathBuf>,
    /// The enterprise managed document.
    pub managed: Option<PathBuf>,
}

impl SettingsPaths {
    /// The real locations for this platform.
    pub fn platform() -> Self {
        Self {
            user_config_dir: std::env::var("CLAUDE_CONFIG_DIR")
                .map(PathBuf::from)
                .ok()
                .or_else(|| dirs::home_dir().map(|home| home.join(".claude"))),
            managed: platform_managed_path(),
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Settings locations installed by [`with_settings_paths`] for one test.
    static TEST_SETTINGS_PATHS: std::cell::RefCell<Option<SettingsPaths>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `body` with `paths` standing in for the host settings locations.
///
/// Thread-local, so parallel tests do not need serializing against each other.
#[cfg(test)]
pub(crate) fn with_settings_paths<T>(paths: SettingsPaths, body: impl FnOnce() -> T) -> T {
    struct Restore(Option<SettingsPaths>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_SETTINGS_PATHS.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }

    let previous = TEST_SETTINGS_PATHS.with(|slot| slot.borrow_mut().replace(paths));
    let _restore = Restore(previous);
    body()
}

/// Locations the loader actually reads.
///
/// Under `cfg(test)` the managed document defaults out unless a test installs
/// one, so a developer machine's real enterprise policy cannot steer the suite.
fn effective_paths() -> SettingsPaths {
    #[cfg(test)]
    {
        TEST_SETTINGS_PATHS
            .with(|slot| slot.borrow().clone())
            .unwrap_or_else(|| SettingsPaths {
                managed: None,
                ..SettingsPaths::platform()
            })
    }
    #[cfg(not(test))]
    {
        SettingsPaths::platform()
    }
}

/// The permission documents from every scope, before a client's source policy
/// decides which of them participate.
#[derive(Debug, Default)]
pub struct SettingsSources {
    /// `~/.claude/settings.json`, or `$CLAUDE_CONFIG_DIR/settings.json`.
    pub user: Option<Settings>,
    /// `.claude/settings.json` under the invocation cwd.
    pub project: Option<Settings>,
    /// `.claude/settings.local.json` under the invocation cwd.
    pub local: Option<Settings>,
    /// The platform's enterprise managed document.
    pub managed: Option<ManagedSettings>,
}

impl SettingsSources {
    /// Read every scope from disk.
    ///
    /// The four documents are the same for every client. tool-gates' own rules
    /// live under `.claude/`, including for Codex and Antigravity: a client's
    /// native permission file is an input to *that client's* engine, and for
    /// Antigravity it is the file `tool-gates agy allowlist` writes a broad
    /// program-level allow list into, so reading it back here would let
    /// `command(find)` approve `find . -delete`.
    pub fn load(cwd: &str) -> Self {
        Self::load_from(&effective_paths(), cwd)
    }

    /// Read every scope, taking the two machine-global documents from `paths`.
    pub fn load_from(paths: &SettingsPaths, cwd: &str) -> Self {
        let user = paths
            .user_config_dir
            .as_ref()
            .and_then(|dir| Settings::load_file(&dir.join("settings.json")));
        let (project, local) = if cwd.is_empty() {
            (None, None)
        } else {
            let root = Path::new(cwd);
            (
                Settings::load_file(&root.join(".claude/settings.json")),
                Settings::load_file(&root.join(".claude/settings.local.json")),
            )
        };
        let managed = paths
            .managed
            .as_ref()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|content| ManagedSettings::parse(&content));

        Self {
            user,
            project,
            local,
            managed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsDecision {
    Allow,
    Deny,
    Ask,
    NoMatch,
}

impl Settings {
    /// Load the effective permission set for `client` at `cwd`.
    ///
    /// `client` is a parameter rather than something the loader infers, because
    /// the managed-only branch below applies to Claude alone and every other
    /// client keeps the four-source merge.
    pub fn load(client: Client, cwd: &str) -> Self {
        Self::resolve(client, SettingsSources::load(cwd))
    }

    /// Apply a client's source policy to documents that have already been read.
    ///
    /// Claude honors the managed document's `allowManagedPermissionRulesOnly`:
    /// when it is boolean `true`, that document is the entire permission set.
    /// The flag draws a source boundary rather than filtering grants, so the
    /// user, project, and local documents drop out completely, their `deny` and
    /// `ask` entries included. An empty managed `permissions` object therefore
    /// resolves to no rules at all, not to a lower scope's rules.
    ///
    /// Every other client merges all four scopes in priority order, lowest
    /// first, exactly as it did before the flag existed.
    pub fn resolve(client: Client, sources: SettingsSources) -> Self {
        let SettingsSources {
            user,
            project,
            local,
            managed,
        } = sources;

        let managed_permissions = match managed {
            Some(doc) if client == Client::Claude && doc.permission_rules_only => {
                return Settings {
                    permissions: doc.permissions,
                };
            }
            Some(doc) => Some(doc.permissions),
            None => None,
        };

        let mut merged = Settings::default();
        for settings in [user, project, local].into_iter().flatten() {
            merged.merge(settings.permissions);
        }
        if let Some(permissions) = managed_permissions {
            merged.merge(permissions);
        }
        merged
    }

    /// Read one lower-scope document. A missing file and an unparseable one
    /// both yield `None`: Claude Code itself skips a settings file it cannot
    /// read, and refusing to gate at all would be the less safe divergence.
    fn load_file(path: &Path) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    fn merge(&mut self, other: Permissions) {
        self.permissions.allow.extend(other.allow);
        self.permissions.deny.extend(other.deny);
        self.permissions.ask.extend(other.ask);
        self.permissions
            .additional_directories
            .extend(other.additional_directories);
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

    /// Return the first deny pattern that matches `command`, if any.
    /// Used to surface the specific rule in the deny reason so the agent
    /// can learn what to avoid instead of seeing a generic "matched a rule".
    pub fn matched_deny_pattern(&self, command: &str) -> Option<&str> {
        self.find_matching(&self.permissions.deny, command)
    }

    /// Like `matches_any` but returns the matched pattern instead of a bool.
    fn find_matching<'a>(&self, patterns: &'a [String], command: &str) -> Option<&'a str> {
        for pattern in patterns {
            if let Some(inner) = strip_command_pattern(pattern)
                && Self::matches_bash_pattern(inner, command)
            {
                return Some(pattern);
            }
        }
        None
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

    /// Check a file path against settings.json file-tool rules (`Write(...)`,
    /// `Edit(...)`, `MultiEdit(...)`). Mirrors Claude's file permissions onto
    /// Codex's `apply_patch`, which carries no tool name a settings rule keys on.
    ///
    /// Each path is matched against both its absolute form and an optional
    /// cwd-relative form, so patterns written either way (`**/.env*`,
    /// `src/**`, `/abs/path/**`) match. Priority: deny, then ask, then allow.
    pub fn check_file_path(&self, abs_path: &str, rel_path: Option<&str>) -> SettingsDecision {
        if Self::matches_file_patterns(&self.permissions.deny, abs_path, rel_path) {
            return SettingsDecision::Deny;
        }
        if Self::matches_file_patterns(&self.permissions.ask, abs_path, rel_path) {
            return SettingsDecision::Ask;
        }
        if Self::matches_file_patterns(&self.permissions.allow, abs_path, rel_path) {
            return SettingsDecision::Allow;
        }
        SettingsDecision::NoMatch
    }

    /// Match a path against the file-tool patterns in a rule list. Recognizes
    /// `Write(...)`, `Edit(...)`, and `MultiEdit(...)`; `apply_patch` adds,
    /// updates, and deletes files, so all three prefixes apply to its paths.
    fn matches_file_patterns(patterns: &[String], abs_path: &str, rel_path: Option<&str>) -> bool {
        const FILE_PREFIXES: &[&str] = &["Write(", "Edit(", "MultiEdit("];
        for pattern in patterns {
            for prefix in FILE_PREFIXES {
                if let Some(rest) = pattern.strip_prefix(prefix)
                    && let Some(inner) = rest.strip_suffix(')')
                    && (path_matches_glob(inner, abs_path)
                        || rel_path.is_some_and(|r| path_matches_glob(inner, r)))
                {
                    return true;
                }
            }
        }
        false
    }

    /// Match command against Bash(...) or command(...) patterns
    fn matches_any(&self, patterns: &[String], command: &str) -> bool {
        for pattern in patterns {
            if let Some(inner) = strip_command_pattern(pattern)
                && Self::matches_bash_pattern(inner, command)
            {
                return true;
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

    /// Highest specificity score among all matching Bash/command patterns in the list.
    fn best_match_specificity(patterns: &[String], command: &str) -> Option<usize> {
        let mut best: Option<usize> = None;
        for pattern in patterns {
            if let Some(inner) = strip_command_pattern(pattern)
                && let Some(score) = Self::pattern_specificity(inner, command)
            {
                best = Some(best.map_or(score, |b| b.max(score)));
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

/// Hermetic settings fixtures shared by the tests in this crate.
///
/// Every scope is written under one temporary directory, so a test can prove
/// what a managed document excludes without touching the host's real user or
/// enterprise settings.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::{SettingsPaths, with_settings_paths};
    use std::fs;
    use std::path::PathBuf;

    pub(crate) struct SettingsFixture {
        _root: tempfile::TempDir,
        /// Canonical form of the temp root, so a path written into a fixture
        /// document compares equal to the same path after symlink resolution.
        path: PathBuf,
    }

    impl SettingsFixture {
        pub(crate) fn new() -> Self {
            let root = tempfile::TempDir::new().expect("tempdir for settings fixture");
            let path = fs::canonicalize(root.path()).expect("canonical fixture root");
            fs::create_dir_all(path.join("project/.claude")).expect("project dir");
            fs::create_dir_all(path.join("user-config")).expect("user config dir");
            fs::create_dir_all(path.join("managed")).expect("managed dir");
            Self { _root: root, path }
        }

        /// The invocation cwd the project and local documents belong to.
        pub(crate) fn cwd(&self) -> String {
            self.path.join("project").to_string_lossy().into_owned()
        }

        /// A synthetic directory inside the fixture, for `additionalDirectories`.
        pub(crate) fn dir(&self, name: &str) -> String {
            let path = self.path.join(name);
            fs::create_dir_all(&path).expect("fixture directory");
            path.to_string_lossy().into_owned()
        }

        pub(crate) fn with_user(self, json: &str) -> Self {
            self.write("user-config/settings.json", json)
        }

        pub(crate) fn with_project(self, json: &str) -> Self {
            self.write("project/.claude/settings.json", json)
        }

        pub(crate) fn with_local(self, json: &str) -> Self {
            self.write("project/.claude/settings.local.json", json)
        }

        pub(crate) fn with_managed(self, json: &str) -> Self {
            self.write("managed/managed-settings.json", json)
        }

        /// Write an arbitrary file under the fixture root, for tests that need
        /// a `mise.toml` or `package.json` beside the settings documents.
        pub(crate) fn write_file(self, relative: &str, contents: &str) -> Self {
            self.write(relative, contents)
        }

        fn write(self, relative: &str, contents: &str) -> Self {
            fs::write(self.path.join(relative), contents).expect("fixture write");
            self
        }

        pub(crate) fn paths(&self) -> SettingsPaths {
            SettingsPaths {
                user_config_dir: Some(self.path.join("user-config")),
                managed: Some(self.managed_path()),
            }
        }

        fn managed_path(&self) -> PathBuf {
            self.path.join("managed/managed-settings.json")
        }

        /// Run `body` with this fixture standing in for the host locations.
        pub(crate) fn run<T>(&self, body: impl FnOnce() -> T) -> T {
            with_settings_paths(self.paths(), body)
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
    fn test_command_wrapper_matching() {
        let settings = Settings {
            permissions: Permissions {
                allow: vec!["command(cargo test:*)".to_string()],
                deny: vec!["command(cargo publish)".to_string()],
                ask: vec!["command(git:*)".to_string()],
                ..Default::default()
            },
        };

        assert_eq!(
            settings.check_command("cargo test --all"),
            SettingsDecision::Allow
        );
        assert_eq!(
            settings.check_command("cargo publish"),
            SettingsDecision::Deny
        );
        assert_eq!(settings.check_command("git push"), SettingsDecision::Ask);
        assert_eq!(
            settings.check_command("echo hello"),
            SettingsDecision::NoMatch
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

    #[serial_test::serial]
    #[test]
    fn test_dollar_user_expansion_in_deny_pattern() {
        let user = std::env::var("USER").unwrap_or_else(|_| "nobody".to_string());

        let settings = Settings {
            permissions: Permissions {
                deny: vec!["Bash(rm /tmp/$USER/.ssh/*)".to_string()],
                ..Default::default()
            },
        };

        let cmd = format!("rm /tmp/{user}/.ssh/id_rsa");
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

/// Managed-only source selection: the `allowManagedPermissionRulesOnly` branch
/// of [`Settings::resolve`], proved through the real loader against synthetic
/// documents.
#[cfg(test)]
mod managed_only_tests {
    use super::fixtures::SettingsFixture;
    use super::*;

    const USER_JSON: &str = r#"{
        "permissions": {
            "allow": ["Bash(user-allowed:*)"],
            "deny": ["Bash(user-denied:*)"],
            "ask": ["Bash(user-asked:*)"],
            "additionalDirectories": ["/synthetic/user-dir"]
        }
    }"#;

    const PROJECT_JSON: &str = r#"{
        "permissions": {
            "allow": ["Bash(project-allowed:*)"],
            "deny": ["Bash(project-denied:*)"],
            "ask": ["Bash(project-asked:*)"],
            "additionalDirectories": ["/synthetic/project-dir"]
        }
    }"#;

    const LOCAL_JSON: &str = r#"{
        "permissions": {
            "allow": ["Bash(local-allowed:*)"],
            "deny": ["Bash(local-denied:*)"],
            "ask": ["Bash(local-asked:*)"],
            "additionalDirectories": ["/synthetic/local-dir"]
        }
    }"#;

    const MANAGED_RULES: &str = r#"
            "permissions": {
                "allow": ["Bash(managed-allowed:*)"],
                "deny": ["Bash(managed-denied:*)"],
                "ask": ["Bash(managed-asked:*)"],
                "additionalDirectories": ["/synthetic/managed-dir"]
            }"#;

    /// A managed document with `MANAGED_RULES` and the given top-level flag
    /// literal, or no flag line when `flag` is `None`.
    fn managed_doc(flag: Option<&str>) -> String {
        match flag {
            Some(value) => format!(
                "{{\n            \"allowManagedPermissionRulesOnly\": {value},{MANAGED_RULES}\n        }}"
            ),
            None => format!("{{{MANAGED_RULES}\n        }}"),
        }
    }

    /// A fixture carrying every lower scope, so each assertion below shows what
    /// the managed document does or does not exclude.
    fn all_lower_scopes() -> SettingsFixture {
        SettingsFixture::new()
            .with_user(USER_JSON)
            .with_project(PROJECT_JSON)
            .with_local(LOCAL_JSON)
    }

    fn decision(settings: &Settings, command: &str) -> SettingsDecision {
        settings.check_command(command)
    }

    /// Assert every rule class from every lower scope is absent.
    fn assert_lower_scopes_excluded(settings: &Settings) {
        for scope in ["user", "project", "local"] {
            for class in ["allowed", "denied", "asked"] {
                let command = format!("{scope}-{class} run");
                assert_eq!(
                    decision(settings, &command),
                    SettingsDecision::NoMatch,
                    "{command} must not match a lower-scope rule under managed-only resolution"
                );
            }
        }
    }

    fn assert_managed_rules_active(settings: &Settings) {
        assert_eq!(
            decision(settings, "managed-allowed run"),
            SettingsDecision::Allow
        );
        assert_eq!(
            decision(settings, "managed-denied run"),
            SettingsDecision::Deny
        );
        assert_eq!(
            decision(settings, "managed-asked run"),
            SettingsDecision::Ask
        );
    }

    fn assert_all_sources_merged(settings: &Settings) {
        for scope in ["user", "project", "local", "managed"] {
            assert_eq!(
                decision(settings, &format!("{scope}-allowed run")),
                SettingsDecision::Allow,
                "{scope} allow rule should participate"
            );
            assert_eq!(
                decision(settings, &format!("{scope}-denied run")),
                SettingsDecision::Deny,
                "{scope} deny rule should participate"
            );
            assert_eq!(
                decision(settings, &format!("{scope}-asked run")),
                SettingsDecision::Ask,
                "{scope} ask rule should participate"
            );
        }
        let dirs = settings.allowed_directories("/synthetic/cwd");
        for scope in ["user", "project", "local", "managed"] {
            let expected = format!("/synthetic/{scope}-dir");
            assert!(
                dirs.contains(&expected),
                "{expected} should participate, got {dirs:?}"
            );
        }
    }

    // === Source-selection matrix ===

    #[test]
    fn claude_managed_flag_true_excludes_every_lower_scope() {
        let fixture = all_lower_scopes().with_managed(&managed_doc(Some("true")));
        let cwd = fixture.cwd();
        let settings = fixture.run(|| Settings::load(Client::Claude, &cwd));

        assert_managed_rules_active(&settings);
        assert_lower_scopes_excluded(&settings);
        assert_eq!(
            settings.allowed_directories(&cwd),
            vec![cwd.clone(), "/synthetic/managed-dir".to_string()]
        );
    }

    #[test]
    fn claude_managed_flag_true_excludes_the_user_scope_alone() {
        let fixture = SettingsFixture::new()
            .with_user(USER_JSON)
            .with_managed(&managed_doc(Some("true")));
        let cwd = fixture.cwd();
        let settings = fixture.run(|| Settings::load(Client::Claude, &cwd));

        assert_managed_rules_active(&settings);
        assert_eq!(
            decision(&settings, "user-allowed run"),
            SettingsDecision::NoMatch
        );
        assert_eq!(
            decision(&settings, "user-denied run"),
            SettingsDecision::NoMatch
        );
        assert_eq!(
            decision(&settings, "user-asked run"),
            SettingsDecision::NoMatch
        );
        assert!(
            !settings
                .allowed_directories(&cwd)
                .contains(&"/synthetic/user-dir".to_string())
        );
    }

    #[test]
    fn claude_managed_flag_true_excludes_the_project_scope_alone() {
        let fixture = SettingsFixture::new()
            .with_project(PROJECT_JSON)
            .with_managed(&managed_doc(Some("true")));
        let cwd = fixture.cwd();
        let settings = fixture.run(|| Settings::load(Client::Claude, &cwd));

        assert_managed_rules_active(&settings);
        assert_eq!(
            decision(&settings, "project-allowed run"),
            SettingsDecision::NoMatch
        );
        assert_eq!(
            decision(&settings, "project-denied run"),
            SettingsDecision::NoMatch
        );
        assert_eq!(
            decision(&settings, "project-asked run"),
            SettingsDecision::NoMatch
        );
        assert!(
            !settings
                .allowed_directories(&cwd)
                .contains(&"/synthetic/project-dir".to_string())
        );
    }

    #[test]
    fn claude_managed_flag_true_excludes_the_local_scope_alone() {
        let fixture = SettingsFixture::new()
            .with_local(LOCAL_JSON)
            .with_managed(&managed_doc(Some("true")));
        let cwd = fixture.cwd();
        let settings = fixture.run(|| Settings::load(Client::Claude, &cwd));

        assert_managed_rules_active(&settings);
        assert_eq!(
            decision(&settings, "local-allowed run"),
            SettingsDecision::NoMatch
        );
        assert_eq!(
            decision(&settings, "local-denied run"),
            SettingsDecision::NoMatch
        );
        assert_eq!(
            decision(&settings, "local-asked run"),
            SettingsDecision::NoMatch
        );
        assert!(
            !settings
                .allowed_directories(&cwd)
                .contains(&"/synthetic/local-dir".to_string())
        );
    }

    #[test]
    fn claude_empty_managed_permissions_resolve_to_no_rules() {
        for managed in [
            r#"{"allowManagedPermissionRulesOnly": true, "permissions": {}}"#,
            r#"{"allowManagedPermissionRulesOnly": true}"#,
        ] {
            let fixture = all_lower_scopes().with_managed(managed);
            let cwd = fixture.cwd();
            let settings = fixture.run(|| Settings::load(Client::Claude, &cwd));

            assert_lower_scopes_excluded(&settings);
            assert_eq!(settings.allowed_directories(&cwd), vec![cwd.clone()]);
        }
    }

    #[test]
    fn claude_malformed_managed_permissions_never_fall_back_to_lower_scopes() {
        // `allow` is a string where the schema wants an array. The document is
        // still valid JSON asserting the flag, so the source boundary holds.
        let fixture = all_lower_scopes().with_managed(
            r#"{
                "allowManagedPermissionRulesOnly": true,
                "permissions": {
                    "allow": "Bash(managed-allowed:*)",
                    "additionalDirectories": ["/synthetic/managed-dir"]
                }
            }"#,
        );
        let cwd = fixture.cwd();
        let settings = fixture.run(|| Settings::load(Client::Claude, &cwd));

        assert_lower_scopes_excluded(&settings);
        assert_eq!(
            decision(&settings, "managed-allowed run"),
            SettingsDecision::NoMatch
        );
        assert_eq!(settings.allowed_directories(&cwd), vec![cwd.clone()]);
    }

    #[test]
    fn claude_managed_flag_false_keeps_the_four_source_merge() {
        let fixture = all_lower_scopes().with_managed(&managed_doc(Some("false")));
        let cwd = fixture.cwd();
        let settings = fixture.run(|| Settings::load(Client::Claude, &cwd));

        assert_all_sources_merged(&settings);
    }

    #[test]
    fn claude_absent_managed_flag_keeps_the_four_source_merge() {
        let fixture = all_lower_scopes().with_managed(&managed_doc(None));
        let cwd = fixture.cwd();
        let settings = fixture.run(|| Settings::load(Client::Claude, &cwd));

        assert_all_sources_merged(&settings);
    }

    #[test]
    fn claude_non_boolean_managed_flag_keeps_the_four_source_merge() {
        for literal in [r#""true""#, "1", "null", r#"["true"]"#] {
            let fixture = all_lower_scopes().with_managed(&managed_doc(Some(literal)));
            let cwd = fixture.cwd();
            let settings = fixture.run(|| Settings::load(Client::Claude, &cwd));

            assert_all_sources_merged(&settings);
        }
    }

    #[test]
    fn claude_absent_managed_file_keeps_the_lower_scopes() {
        let fixture = all_lower_scopes();
        let cwd = fixture.cwd();
        let settings = fixture.run(|| Settings::load(Client::Claude, &cwd));

        for scope in ["user", "project", "local"] {
            assert_eq!(
                decision(&settings, &format!("{scope}-allowed run")),
                SettingsDecision::Allow
            );
            assert_eq!(
                decision(&settings, &format!("{scope}-denied run")),
                SettingsDecision::Deny
            );
            assert_eq!(
                decision(&settings, &format!("{scope}-asked run")),
                SettingsDecision::Ask
            );
        }
    }

    #[test]
    fn a_lower_scope_cannot_assert_the_managed_flag() {
        let flagged_user = format!(
            r#"{{"allowManagedPermissionRulesOnly": true, {}}}"#,
            USER_JSON
                .trim()
                .trim_start_matches('{')
                .trim_end_matches('}')
        );
        let fixture = SettingsFixture::new()
            .with_user(&flagged_user)
            .with_project(PROJECT_JSON)
            .with_local(LOCAL_JSON)
            .with_managed(&managed_doc(None));
        let cwd = fixture.cwd();
        let settings = fixture.run(|| Settings::load(Client::Claude, &cwd));

        assert_all_sources_merged(&settings);
    }

    #[test]
    fn other_clients_ignore_the_managed_flag() {
        for client in [Client::Codex, Client::Antigravity, Client::Gemini] {
            let fixture = all_lower_scopes().with_managed(&managed_doc(Some("true")));
            let cwd = fixture.cwd();
            let settings = fixture.run(|| Settings::load(client, &cwd));

            assert_all_sources_merged(&settings);
        }
    }

    // === Decision regressions under the managed flag ===

    /// Build a Claude settings set from a managed-only document plus the given
    /// lower-scope documents.
    fn managed_only_with(
        managed: &str,
        user: Option<&str>,
        project: Option<&str>,
        local: Option<&str>,
    ) -> (Settings, String) {
        let mut fixture = SettingsFixture::new().with_managed(managed);
        if let Some(json) = user {
            fixture = fixture.with_user(json);
        }
        if let Some(json) = project {
            fixture = fixture.with_project(json);
        }
        if let Some(json) = local {
            fixture = fixture.with_local(json);
        }
        let cwd = fixture.cwd();
        let settings = fixture.run(|| Settings::load(Client::Claude, &cwd));
        (settings, cwd)
    }

    #[test]
    fn lower_allow_cannot_override_a_managed_ask_or_deny() {
        let (settings, _cwd) = managed_only_with(
            r#"{
                "allowManagedPermissionRulesOnly": true,
                "permissions": {
                    "ask": ["Bash(deploy:*)"],
                    "deny": ["Bash(publish:*)"]
                }
            }"#,
            Some(r#"{"permissions": {"allow": ["Bash(deploy:*)", "Bash(publish:*)"]}}"#),
            None,
            None,
        );

        assert_eq!(decision(&settings, "deploy staging"), SettingsDecision::Ask);
        assert_eq!(
            decision(&settings, "publish my-service"),
            SettingsDecision::Deny
        );
    }

    #[test]
    fn lower_deny_cannot_override_a_managed_allow() {
        let (settings, _cwd) = managed_only_with(
            r#"{
                "allowManagedPermissionRulesOnly": true,
                "permissions": {"allow": ["Bash(mytool:*)"]}
            }"#,
            None,
            None,
            Some(r#"{"permissions": {"deny": ["Bash(mytool:*)"]}}"#),
        );

        assert_eq!(decision(&settings, "mytool build"), SettingsDecision::Allow);
    }

    #[test]
    fn specificity_is_evaluated_only_among_managed_rules() {
        let (settings, _cwd) = managed_only_with(
            r#"{
                "allowManagedPermissionRulesOnly": true,
                "permissions": {"ask": ["Bash(mytool:*)"]}
            }"#,
            None,
            Some(r#"{"permissions": {"allow": ["Bash(mytool --config production:*)"]}}"#),
            None,
        );

        // The lower allow is longer, so it would win on specificity if it were
        // in the participating set at all.
        assert_eq!(
            decision(&settings, "mytool --config production deploy"),
            SettingsDecision::Ask
        );
    }

    #[test]
    fn lower_additional_directories_are_excluded_and_managed_ones_remain() {
        let (settings, cwd) = managed_only_with(
            r#"{
                "allowManagedPermissionRulesOnly": true,
                "permissions": {"additionalDirectories": ["/synthetic/managed-dir"]}
            }"#,
            Some(r#"{"permissions": {"additionalDirectories": ["/synthetic/user-dir"]}}"#),
            Some(r#"{"permissions": {"additionalDirectories": ["/synthetic/project-dir"]}}"#),
            Some(r#"{"permissions": {"additionalDirectories": ["/synthetic/local-dir"]}}"#),
        );

        assert_eq!(
            settings.allowed_directories(&cwd),
            vec![cwd.clone(), "/synthetic/managed-dir".to_string()]
        );
    }

    #[test]
    fn managed_write_rules_apply_and_lower_write_rules_do_not() {
        let (settings, _cwd) = managed_only_with(
            r#"{
                "allowManagedPermissionRulesOnly": true,
                "permissions": {"deny": ["Write(**/.env*)"]}
            }"#,
            Some(r#"{"permissions": {"allow": ["Write(/synthetic/project/**)"]}}"#),
            None,
            None,
        );

        assert_eq!(
            settings.check_file_path("/synthetic/project/.env.local", None),
            SettingsDecision::Deny
        );
        assert_eq!(
            settings.check_file_path("/synthetic/project/src/main.rs", None),
            SettingsDecision::NoMatch
        );
    }

    #[test]
    fn managed_mcp_rules_apply_and_lower_mcp_rules_do_not() {
        let (settings, _cwd) = managed_only_with(
            r#"{
                "allowManagedPermissionRulesOnly": true,
                "permissions": {"deny": ["mcp__server-a__dangerous_tool"]}
            }"#,
            Some(r#"{"permissions": {"allow": ["mcp__server-a"]}}"#),
            None,
            None,
        );

        assert_eq!(
            settings.check_mcp_tool("server-a", "dangerous_tool"),
            SettingsDecision::Deny
        );
        assert_eq!(
            settings.check_mcp_tool("server-a", "safe_tool"),
            SettingsDecision::NoMatch
        );
    }

    // === Loader plumbing ===

    #[test]
    fn platform_paths_point_at_the_documented_managed_location() {
        let expected = if cfg!(target_os = "linux") {
            Some("/etc/claude-code/managed-settings.json")
        } else if cfg!(target_os = "macos") {
            Some("/Library/Application Support/ClaudeCode/managed-settings.json")
        } else if cfg!(target_os = "windows") {
            Some("C:\\Program Files\\ClaudeCode\\managed-settings.json")
        } else {
            None
        };

        assert_eq!(
            SettingsPaths::platform()
                .managed
                .map(|p| p.to_string_lossy().into_owned()),
            expected.map(str::to_string)
        );
    }

    #[test]
    fn an_unparseable_managed_document_leaves_the_managed_scope_out() {
        let fixture = all_lower_scopes().with_managed("{ this is not json");
        let cwd = fixture.cwd();
        let sources = fixture.run(|| SettingsSources::load(&cwd));

        assert!(sources.managed.is_none());
        assert!(sources.user.is_some());

        let settings = Settings::resolve(Client::Claude, sources);
        assert_eq!(
            decision(&settings, "user-allowed run"),
            SettingsDecision::Allow
        );
    }

    #[test]
    fn resolve_is_pure_over_supplied_documents() {
        let sources = SettingsSources {
            user: Some(Settings {
                permissions: Permissions {
                    allow: vec!["Bash(user-allowed:*)".to_string()],
                    ..Default::default()
                },
            }),
            project: None,
            local: None,
            managed: Some(ManagedSettings {
                permission_rules_only: true,
                permissions: Permissions {
                    allow: vec!["Bash(managed-allowed:*)".to_string()],
                    ..Default::default()
                },
            }),
        };

        let settings = Settings::resolve(Client::Claude, sources);
        assert_eq!(
            decision(&settings, "managed-allowed run"),
            SettingsDecision::Allow
        );
        assert_eq!(
            decision(&settings, "user-allowed run"),
            SettingsDecision::NoMatch
        );
    }
}

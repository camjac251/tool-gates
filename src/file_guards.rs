//! Symlink guard for AI config files.
//!
//! When Claude encounters a symlinked config file (e.g. CLAUDE.md -> ../shared/CLAUDE.md),
//! it tries to read both the symlink and the source, then commits the wrong one.
//! This guard blocks the symlink read and tells Claude the real path.
//!
//! Only fires on known AI assistant instruction/config filenames. All other
//! symlinks pass through untouched. The guarded names and directories can be
//! extended via `[file_guards]` in the config TOML.

use std::path::Path;

use crate::config::FileGuardsConfig;
use crate::models::HookOutput;

/// Exact filename matches (case-insensitive).
const GUARDED_NAMES: &[&str] = &[
    // AGENTS.md open standard
    "agents.md",
    "agent.md",
    // Claude Code
    "claude.md",
    "claude.local.md",
    // Gemini CLI
    "gemini.md",
    ".geminiignore",
    // GitHub Copilot
    "copilot-instructions.md",
    // Cursor
    ".cursorrules",
    ".cursorignore",
    // Windsurf / Codeium
    ".windsurfrules",
    ".codeiumignore",
    // Cline
    ".clinerules",
    // Roo Code
    ".roorules",
    ".rooignore",
    // Aider
    ".aider.conf.yml",
    ".aiderignore",
    ".aider.model.settings.yml",
    ".aider.model.metadata.json",
    // Zed
    ".rules",
    // OpenAI Codex CLI
    ".agentignore",
    // JetBrains AI Assistant
    ".aiignore",
    // Gemini Code Assist
    ".aiexclude",
];

/// Prefix matches for mode-specific files (e.g. .roorules-code, .roorules-architect).
const GUARDED_PREFIXES: &[&str] = &[".roorules-"];

/// Parent directory names that indicate AI config directories.
/// Any config-extension file inside these dirs is guarded.
const GUARDED_DIRS: &[&str] = &[
    ".claude",
    ".cursor",
    ".continue",
    ".github",
    ".gemini",
    ".roo",
    ".amazonq",
    ".zed",
    ".clinerules",
    ".windsurf",
    ".codex",
];

/// File extensions considered config within guarded directories.
const CONFIG_EXTENSIONS: &[&str] = &[".md", ".mdc", ".yml", ".yaml", ".json"];

/// Check if a path looks like an AI coding config file.
///
/// Uses built-in lists merged with any user-configured extras.
fn is_guarded(path: &Path, extra: &FileGuardsConfig) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };

    // Direct filename match (built-in + extras)
    if GUARDED_NAMES.iter().any(|&g| g == name) {
        return true;
    }
    if extra
        .extra_names
        .iter()
        .any(|g| g.to_ascii_lowercase() == name)
    {
        return true;
    }

    // Prefix match (built-in + extras)
    if GUARDED_PREFIXES.iter().any(|&pfx| name.starts_with(pfx)) {
        return true;
    }
    if extra
        .extra_prefixes
        .iter()
        .any(|pfx| name.starts_with(&pfx.to_ascii_lowercase()))
    {
        return true;
    }

    // Config file inside a guarded directory
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e.to_ascii_lowercase()));

    if let Some(ref ext) = ext {
        let is_config_ext = CONFIG_EXTENSIONS.contains(&ext.as_str())
            || extra
                .extra_extensions
                .iter()
                .any(|e| e.to_ascii_lowercase() == *ext);

        if is_config_ext {
            for ancestor in path.ancestors().skip(1) {
                if let Some(dir_name) = ancestor.file_name().and_then(|n| n.to_str()) {
                    let dir_lower = dir_name.to_ascii_lowercase();
                    if GUARDED_DIRS.iter().any(|&g| g == dir_lower) {
                        return true;
                    }
                    if extra
                        .extra_dirs
                        .iter()
                        .any(|g| g.to_ascii_lowercase() == dir_lower)
                    {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Check a file path for symlinked AI config files.
///
/// Returns `Some(HookOutput)` with a deny if the path is a guarded symlink,
/// or `None` if the file should pass through.
pub fn check_file_guard(
    file_path: &str,
    tool_name: &str,
    extra: &FileGuardsConfig,
) -> Option<HookOutput> {
    if file_path.is_empty() {
        return None;
    }

    let path = Path::new(file_path);

    // Only act on symlinks
    if !path.is_symlink() {
        return None;
    }

    // Only guard AI config files
    if !is_guarded(path, extra) {
        return None;
    }

    // Resolve the symlink target
    let resolved = match path.canonicalize() {
        Ok(r) => r,
        Err(_) => return None, // Broken symlink, let the tool handle it
    };

    // Prefer relative display path when target is nearby
    let display = path
        .parent()
        .and_then(|p| p.canonicalize().ok())
        .and_then(|parent| resolved.strip_prefix(&parent).ok().map(|r| r.to_path_buf()))
        .unwrap_or_else(|| resolved.clone());

    use crate::models::Client;
    let verb = if Client::is_read_tool(tool_name) {
        "Read"
    } else {
        "Edit"
    };
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");

    Some(HookOutput::deny(&format!(
        "{name} is a symlink to {display}. {verb} {display} directly instead.",
        display = display.display(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_extras() -> FileGuardsConfig {
        FileGuardsConfig::default()
    }

    #[test]
    fn test_guarded_names() {
        let e = no_extras();
        assert!(is_guarded(Path::new("/project/CLAUDE.md"), &e));
        assert!(is_guarded(Path::new("/project/claude.md"), &e));
        assert!(is_guarded(Path::new("/project/AGENTS.md"), &e));
        assert!(is_guarded(Path::new("/project/.cursorrules"), &e));
        assert!(is_guarded(Path::new("/project/.windsurfrules"), &e));
        assert!(is_guarded(Path::new("/project/.aiderignore"), &e));
        assert!(is_guarded(Path::new("/project/.agentignore"), &e));
        assert!(is_guarded(Path::new("/project/.aiignore"), &e));
        assert!(is_guarded(Path::new("/project/.aiexclude"), &e));
        assert!(is_guarded(Path::new("/project/gemini.md"), &e));
    }

    #[test]
    fn test_guarded_prefixes() {
        let e = no_extras();
        assert!(is_guarded(Path::new("/project/.roorules-code"), &e));
        assert!(is_guarded(Path::new("/project/.roorules-architect"), &e));
    }

    #[test]
    fn test_guarded_dirs() {
        let e = no_extras();
        assert!(is_guarded(
            Path::new("/project/.claude/rules/my-rule.md"),
            &e
        ));
        assert!(is_guarded(
            Path::new("/project/.cursor/rules/my-rule.mdc"),
            &e
        ));
        assert!(is_guarded(
            Path::new("/project/.github/copilot-instructions.md"),
            &e
        ));
        assert!(is_guarded(Path::new("/project/.gemini/settings.json"), &e));
        assert!(is_guarded(Path::new("/project/.roo/rules/review.md"), &e));
        assert!(is_guarded(
            Path::new("/project/.amazonq/rules/coding.md"),
            &e
        ));
        assert!(is_guarded(Path::new("/project/.zed/rules/main.md"), &e));
        assert!(is_guarded(Path::new("/project/.clinerules/my-rule.md"), &e));
        assert!(is_guarded(
            Path::new("/project/.windsurf/rules/config.md"),
            &e
        ));
        assert!(is_guarded(
            Path::new("/project/.continue/rules/style.md"),
            &e
        ));
    }

    #[test]
    fn test_non_guarded_files() {
        let e = no_extras();
        assert!(!is_guarded(Path::new("/project/README.md"), &e));
        assert!(!is_guarded(Path::new("/project/src/main.rs"), &e));
        assert!(!is_guarded(Path::new("/project/package.json"), &e));
        assert!(!is_guarded(Path::new("/project/.config/something.yml"), &e));
    }

    #[test]
    fn test_non_config_extension_in_guarded_dir() {
        let e = no_extras();
        assert!(!is_guarded(Path::new("/project/.claude/build.rs"), &e));
        assert!(!is_guarded(Path::new("/project/.claude/config.toml"), &e));
    }

    #[test]
    fn test_extra_names() {
        let e = FileGuardsConfig {
            extra_names: vec![".teamrules".to_string()],
            ..Default::default()
        };
        assert!(is_guarded(Path::new("/project/.teamrules"), &e));
        assert!(is_guarded(Path::new("/project/.TEAMRULES"), &e));
        // Built-ins still work
        assert!(is_guarded(Path::new("/project/CLAUDE.md"), &e));
    }

    #[test]
    fn test_extra_dirs() {
        let e = FileGuardsConfig {
            extra_dirs: vec![".myide".to_string()],
            ..Default::default()
        };
        assert!(is_guarded(Path::new("/project/.myide/config.json"), &e));
        assert!(is_guarded(Path::new("/project/.myide/rules.md"), &e));
        // Non-config extension still excluded
        assert!(!is_guarded(Path::new("/project/.myide/main.rs"), &e));
    }

    #[test]
    fn test_extra_prefixes() {
        let e = FileGuardsConfig {
            extra_prefixes: vec![".myrules-".to_string()],
            ..Default::default()
        };
        assert!(is_guarded(Path::new("/project/.myrules-lint"), &e));
        assert!(is_guarded(Path::new("/project/.myrules-format"), &e));
    }

    #[test]
    fn test_extra_extensions() {
        let e = FileGuardsConfig {
            extra_extensions: vec![".toml".to_string()],
            ..Default::default()
        };
        // .toml now counts as config in guarded dirs
        assert!(is_guarded(Path::new("/project/.claude/config.toml"), &e));
        // Still not guarded outside guarded dirs
        assert!(!is_guarded(Path::new("/project/Cargo.toml"), &e));
    }

    #[test]
    fn test_check_non_symlink_passes() {
        let result = check_file_guard("/etc/hosts", "Read", &no_extras());
        assert!(result.is_none());
    }

    #[test]
    fn test_check_empty_path_passes() {
        let result = check_file_guard("", "Read", &no_extras());
        assert!(result.is_none());
    }

    #[test]
    fn test_check_symlink_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let real_file = tmp.path().join("real-claude.md");
        std::fs::write(&real_file, "# Config").unwrap();

        let symlink = tmp.path().join("CLAUDE.md");
        std::os::unix::fs::symlink(&real_file, &symlink).unwrap();

        let result = check_file_guard(symlink.to_str().unwrap(), "Read", &no_extras());
        assert!(result.is_some());

        let json = serde_json::to_string(&result.unwrap().serialize(crate::models::Client::Claude))
            .unwrap();
        assert!(json.contains("deny"));
        assert!(json.contains("symlink"));
        assert!(json.contains("real-claude.md"));
    }

    #[test]
    fn test_check_non_guarded_symlink_passes() {
        let tmp = tempfile::tempdir().unwrap();
        let real_file = tmp.path().join("real-readme.md");
        std::fs::write(&real_file, "# Readme").unwrap();

        let symlink = tmp.path().join("README.md");
        std::os::unix::fs::symlink(&real_file, &symlink).unwrap();

        let result = check_file_guard(symlink.to_str().unwrap(), "Read", &no_extras());
        assert!(result.is_none());
    }

    #[test]
    fn test_check_verb_for_edit() {
        let tmp = tempfile::tempdir().unwrap();
        let real_file = tmp.path().join("real-claude.md");
        std::fs::write(&real_file, "# Config").unwrap();

        let symlink = tmp.path().join("CLAUDE.md");
        std::os::unix::fs::symlink(&real_file, &symlink).unwrap();

        let result = check_file_guard(symlink.to_str().unwrap(), "Edit", &no_extras());
        let json = serde_json::to_string(&result.unwrap().serialize(crate::models::Client::Claude))
            .unwrap();
        assert!(json.contains("Edit"));
    }

    #[test]
    fn test_check_extra_name_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let real_file = tmp.path().join("real-teamrules");
        std::fs::write(&real_file, "rules").unwrap();

        let symlink = tmp.path().join(".teamrules");
        std::os::unix::fs::symlink(&real_file, &symlink).unwrap();

        let e = FileGuardsConfig {
            extra_names: vec![".teamrules".to_string()],
            ..Default::default()
        };
        let result = check_file_guard(symlink.to_str().unwrap(), "Read", &e);
        assert!(result.is_some());
    }

    #[test]
    fn test_guarded_dir_nested() {
        let e = no_extras();
        assert!(is_guarded(
            Path::new("/project/.cursor/rules/sub/deep/rule.mdc"),
            &e
        ));
    }

    #[test]
    fn test_case_insensitive_filename() {
        let e = no_extras();
        assert!(is_guarded(Path::new("/project/Claude.md"), &e));
        assert!(is_guarded(Path::new("/project/CLAUDE.MD"), &e));
    }

    #[test]
    fn test_claude_local_md() {
        let e = no_extras();
        assert!(is_guarded(Path::new("/project/claude.local.md"), &e));
        assert!(is_guarded(Path::new("/project/CLAUDE.LOCAL.MD"), &e));
    }

    #[test]
    fn test_codex_dir() {
        let e = no_extras();
        assert!(is_guarded(Path::new("/project/.codex/config.json"), &e));
    }

    #[test]
    fn test_continue_dir() {
        let e = no_extras();
        assert!(is_guarded(Path::new("/project/.continue/config.yaml"), &e));
    }
}

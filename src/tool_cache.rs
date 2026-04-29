//! Tool availability cache for modern CLI hints.
//!
//! Detects which modern CLI tools are installed and caches the results
//! to avoid repeated `which` calls on every command.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

/// Get the effective cache TTL in seconds (from config or default of 7 days).
fn cache_ttl_secs() -> u64 {
    let days = crate::config::get().cache.ttl_days;
    u64::from(days) * 24 * 60 * 60
}

/// Modern CLI tools to detect and cache. Each tool here must have a corresponding
/// hint in `hints.rs` (as `modern_command`). Tools only used via user-configured
/// `requires_tool` in block rules don't need to be here. `is_available()` falls
/// back to a live `which` check for tools not in this list.
const MODERN_TOOLS: &[&str] = &[
    // File viewing
    "bat", "batcat", // bat is sometimes installed as batcat on Debian/Ubuntu
    // Code search
    "rg", "ripgrep", // ripgrep - faster grep (may be installed as either)
    "sg", "ast-grep", // ast-grep (often invoked as sg)
    // File finding
    "fd", "fdfind", // fd is sometimes fdfind on Debian/Ubuntu
    // File listing
    "eza", // modern ls with git integration
    // Text processing
    "sd",     // modern sed - simpler syntax
    "choose", // modern awk field selection
    // Disk usage
    "dust", // modern du - visual tree
    // Process viewing
    "procs", // modern ps - better formatting
    // HTTP (API exploration)
    "xh", // modern curl/wget - cleaner output
    // Code stats
    "tokei", // modern cloc - faster
    // Hex viewing
    "hexyl", // modern xxd/hexdump - colored
    // Diff viewing
    "difft", // difftastic - structural diff
    // Documentation
    "tldr", "tealdeer", // simplified man pages with examples
];

/// Cached tool availability data
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ToolCache {
    /// Map of tool name -> is_available
    pub tools: HashMap<String, bool>,
    /// When the cache was last updated (Unix timestamp)
    pub checked_at: u64,
}

impl ToolCache {
    /// Check if a specific tool is available
    pub fn is_available(&self, tool: &str) -> bool {
        // Handle aliases (some tools have different names on different distros).
        // Each branch also consults the in-process re-probe map so that a tool
        // installed after the on-disk cache was written can flip to true
        // mid-session via `refresh_tool`.
        match tool {
            "bat" => {
                self.tools.get("bat").copied().unwrap_or(false)
                    || self.tools.get("batcat").copied().unwrap_or(false)
                    || reprobed_positive("bat")
                    || reprobed_positive("batcat")
            }
            "fd" => {
                self.tools.get("fd").copied().unwrap_or(false)
                    || self.tools.get("fdfind").copied().unwrap_or(false)
                    || reprobed_positive("fd")
                    || reprobed_positive("fdfind")
            }
            "rg" => {
                self.tools.get("rg").copied().unwrap_or(false)
                    || self.tools.get("ripgrep").copied().unwrap_or(false)
                    || reprobed_positive("rg")
                    || reprobed_positive("ripgrep")
            }
            "sg" => {
                self.tools.get("sg").copied().unwrap_or(false)
                    || self.tools.get("ast-grep").copied().unwrap_or(false)
                    || reprobed_positive("sg")
                    || reprobed_positive("ast-grep")
            }
            "tldr" => {
                self.tools.get("tldr").copied().unwrap_or(false)
                    || self.tools.get("tealdeer").copied().unwrap_or(false)
                    || reprobed_positive("tldr")
                    || reprobed_positive("tealdeer")
            }
            _ => {
                if self.tools.get(tool).copied().unwrap_or(false) {
                    return true;
                }
                if reprobed_positive(tool) {
                    return true;
                }
                // Tool not in cache (not a modern tool hint target).
                // Fall back to live `which` check for requires_tool and similar.
                check_tool_available(tool)
            }
        }
    }

    /// Check if cache is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        if self.checked_at == 0 {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now.saturating_sub(self.checked_at) < cache_ttl_secs()
    }

    /// Check if the cache contains entries for all known modern tools.
    fn has_all_known_tools(&self) -> bool {
        MODERN_TOOLS
            .iter()
            .all(|tool| self.tools.contains_key(*tool))
    }
}

/// Get the cache file path
fn cache_path() -> Option<PathBuf> {
    Some(crate::cache::cache_dir().join("available-tools.json"))
}

/// Load cache from disk
fn load_cache() -> Option<ToolCache> {
    let path = cache_path()?;
    let content = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Save cache to disk
fn save_cache(cache: &ToolCache) -> Result<(), std::io::Error> {
    let path = cache_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not determine cache path",
        )
    })?;

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let content = serde_json::to_string_pretty(cache)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &content)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Check if a tool is available using `which`
fn check_tool_available(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Detect all modern tools and create a new cache
pub fn detect_tools() -> ToolCache {
    let mut tools = HashMap::new();

    for tool in MODERN_TOOLS {
        tools.insert(tool.to_string(), check_tool_available(tool));
    }

    let checked_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    ToolCache { tools, checked_at }
}

/// Get the tool cache, loading from disk or detecting if needed
pub fn get_cache() -> ToolCache {
    // Try to load existing cache
    if let Some(cache) = load_cache() {
        if cache.is_valid() && cache.has_all_known_tools() {
            return cache;
        }
    }

    // Cache missing or expired - detect tools and save
    let cache = detect_tools();
    let _ = save_cache(&cache); // Ignore save errors
    cache
}

/// Force refresh the cache
pub fn refresh_cache() -> ToolCache {
    let cache = detect_tools();
    let _ = save_cache(&cache);
    cache
}

/// Process-local override for tools that were re-probed during this process
/// after the on-disk cache reported them missing. Prevents repeated `which`
/// calls for the same tool within a single tool-gates invocation, and lets
/// later `is_available` calls in the same process see the fresh answer
/// without paying for another probe.
static REPROBED_TOOLS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, bool>>> =
    std::sync::OnceLock::new();

fn reprobed() -> &'static std::sync::Mutex<HashMap<String, bool>> {
    REPROBED_TOOLS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

pub fn refresh_tool(tool: &str) -> bool {
    {
        let map = reprobed().lock().expect("reprobed mutex poisoned");
        if let Some(&val) = map.get(tool) {
            return val;
        }
    }

    // Probe both canonical and Debian/Ubuntu alias names. Without this,
    // `refresh_tool("bat")` runs `which bat` on Ubuntu where the binary is
    // `batcat`, returns false, and `is_available("bat")` keeps reporting
    // missing even though the user just installed the package.
    let names: &[&str] = match tool {
        "bat" => &["bat", "batcat"],
        "fd" => &["fd", "fdfind"],
        "rg" => &["rg", "ripgrep"],
        "sg" => &["sg", "ast-grep"],
        "tldr" => &["tldr", "tealdeer"],
        other => &[other],
    };

    let mut any_live = false;
    let mut results: Vec<(String, bool)> = Vec::with_capacity(names.len());
    for name in names {
        let live = check_tool_available(name);
        if live {
            any_live = true;
        }
        results.push(((*name).to_string(), live));
    }

    {
        let mut map = reprobed().lock().expect("reprobed mutex poisoned");
        for (name, live) in &results {
            map.insert(name.clone(), *live);
        }
    }

    // Best-effort persist so the next process inherits the fresh answers.
    if let Some(mut cache) = load_cache() {
        for (name, live) in &results {
            cache.tools.insert(name.clone(), *live);
        }
        let _ = save_cache(&cache);
    }

    any_live
}

/// True if the in-process re-probe map already has a positive answer for
/// this tool. Used by `ToolCache::is_available` to short-circuit aliases
/// that were re-probed during the current process.
pub(crate) fn reprobed_positive(tool: &str) -> bool {
    let map = reprobed().lock().expect("reprobed mutex poisoned");
    map.get(tool).copied().unwrap_or(false)
}

/// Get cache status for display
pub fn cache_status() -> String {
    let path = cache_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    if let Some(cache) = load_cache() {
        let age = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_sub(cache.checked_at);

        let age_str = if age < 60 {
            format!("{}s ago", age)
        } else if age < 3600 {
            format!("{}m ago", age / 60)
        } else if age < 86400 {
            format!("{}h ago", age / 3600)
        } else {
            format!("{}d ago", age / 86400)
        };

        let mut available: Vec<_> = cache
            .tools
            .iter()
            .filter(|(_, v)| **v)
            .map(|(k, _)| k.as_str())
            .collect();
        available.sort();

        format!(
            "Cache: {}\nLast checked: {}\nAvailable tools: {}",
            path,
            age_str,
            if available.is_empty() {
                "none".to_string()
            } else {
                available.join(", ")
            }
        )
    } else {
        format!("Cache: {} (not found)", path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_validity() {
        let mut cache = ToolCache::default();
        assert!(!cache.is_valid(), "Empty cache should be invalid");

        cache.checked_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(cache.is_valid(), "Fresh cache should be valid");
    }

    #[test]
    fn test_cache_completeness() {
        let mut cache = ToolCache {
            checked_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ..Default::default()
        };
        cache.tools.insert("bat".to_string(), true);
        assert!(
            !cache.has_all_known_tools(),
            "partial cache should be considered incomplete"
        );
    }

    #[test]
    fn test_tool_aliases() {
        let mut cache = ToolCache::default();
        cache.tools.insert("batcat".to_string(), true);
        cache.tools.insert("fdfind".to_string(), true);
        cache.tools.insert("ast-grep".to_string(), true);

        assert!(cache.is_available("bat"), "bat alias should work");
        assert!(cache.is_available("fd"), "fd alias should work");
        assert!(cache.is_available("sg"), "sg alias should work");
        assert!(
            !cache.is_available("rg"),
            "missing tool should return false"
        );
    }

    #[test]
    fn test_refresh_tool_returns_live_result_for_missing_tool() {
        // Use a name that will never be on PATH so the result is stable
        // across CI environments. Disambiguate from any other test by
        // including a unique stem.
        let bogus = "tool_gates_zzzzz_does_not_exist_001";
        assert!(!refresh_tool(bogus));
        // Re-probe is memoized: a second call should still return false
        // without re-running which.
        assert!(!refresh_tool(bogus));
        assert!(!reprobed_positive(bogus));
    }

    #[test]
    fn test_is_available_consults_reprobed_map_for_alias() {
        // Simulate the disk cache reporting `bat` and `batcat` both missing.
        // After a refresh that flips `bat` to true, is_available must
        // observe it via the alias-aware branch. Use a unique tool name
        // to avoid colliding with the actual tool cache.
        let cache = ToolCache::default();
        // The tool name must be one of the alias-resolved targets in
        // is_available so the branch consults reprobed_positive.
        // Inject a positive into the reprobed map directly to keep the
        // test hermetic (no PATH dependency).
        {
            let mut map = reprobed().lock().expect("mutex");
            map.insert("bat".to_string(), true);
        }
        assert!(cache.is_available("bat"));
        // Cleanup so other tests aren't affected.
        {
            let mut map = reprobed().lock().expect("mutex");
            map.remove("bat");
        }
    }

    #[test]
    fn test_detect_tools() {
        // This actually runs `which` - just verify it doesn't panic
        let cache = detect_tools();
        assert!(cache.checked_at > 0);
        assert!(!cache.tools.is_empty());
    }
}

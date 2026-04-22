//! Block tools based on configurable rules.
//!
//! Rules are defined in `~/.config/tool-gates/config.toml` under `[[block_tools]]`.
//! Each rule can block a tool unconditionally or only when URL fields match
//! specific domains.
//!
//! Built-in defaults (Glob, Grep, firecrawl+GitHub) apply when no
//! `[[block_tools]]` section is present in the config.

use crate::config::BlockRule;
use crate::models::HookOutput;
use crate::tool_cache;

/// Extract domain from a URL string (simple, no external crate).
/// Handles ports (github.com:443) and userinfo (user@github.com).
fn extract_domain(url: &str) -> Option<&str> {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let authority = stripped.split('/').next()?;
    // Strip userinfo (user@host)
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    // Strip port (:443)
    let domain = host_port.split(':').next()?;
    if domain.is_empty() || !domain.contains('.') {
        return None;
    }
    Some(domain)
}

/// Check if a URL matches any of the blocked domains.
fn url_matches_domains(url: &str, domains: &[String]) -> bool {
    if url.is_empty() {
        return false;
    }
    match extract_domain(url) {
        Some(domain) => domains.iter().any(|d| d == domain),
        None => false,
    }
}

/// Extract URLs from tool_input (checks `url` field and `urls` array).
fn extract_urls(tool_input: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut urls = Vec::new();

    if let Some(url) = tool_input.get("url").and_then(|v| v.as_str()) {
        urls.push(url.to_string());
    }

    if let Some(arr) = tool_input.get("urls").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                urls.push(s.to_string());
            }
        }
    }

    urls
}

/// Check a tool call against block rules.
///
/// Returns `Some(HookOutput)` with deny if a rule matches, `None` to pass through.
pub fn check_tool_block(
    tool_name: &str,
    tool_input: &serde_json::Map<String, serde_json::Value>,
    rules: &[BlockRule],
) -> Option<HookOutput> {
    // Lazy-load tool cache only if any rule has requires_tool
    let cache = std::cell::OnceCell::new();
    let get_cache = || cache.get_or_init(tool_cache::get_cache);

    for rule in rules {
        if !rule.matches_tool(tool_name) {
            continue;
        }

        // Skip rule if the required alternative tool isn't installed
        if let Some(ref required) = rule.requires_tool {
            if !get_cache().is_available(required) {
                continue;
            }
        }

        // Unconditional block
        if rule.is_unconditional() {
            return Some(HookOutput::deny(&rule.message));
        }

        // Domain-conditional block: check URL fields
        let urls = extract_urls(tool_input);
        for url in &urls {
            if url_matches_domains(url, &rule.block_domains) {
                return Some(HookOutput::deny(&rule.message));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(tool: &str, message: &str) -> BlockRule {
        BlockRule {
            tool: tool.to_string(),
            message: message.to_string(),
            block_domains: vec![],
            requires_tool: None,
        }
    }

    fn domain_rule(tool: &str, message: &str, domains: &[&str]) -> BlockRule {
        BlockRule {
            tool: tool.to_string(),
            message: message.to_string(),
            block_domains: domains.iter().map(|d| d.to_string()).collect(),
            requires_tool: None,
        }
    }

    fn empty_input() -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }

    fn input_with_url(url: &str) -> serde_json::Map<String, serde_json::Value> {
        let mut m = serde_json::Map::new();
        m.insert(
            "url".to_string(),
            serde_json::Value::String(url.to_string()),
        );
        m
    }

    fn input_with_urls(urls: &[&str]) -> serde_json::Map<String, serde_json::Value> {
        let mut m = serde_json::Map::new();
        m.insert(
            "urls".to_string(),
            serde_json::Value::Array(
                urls.iter()
                    .map(|u| serde_json::Value::String(u.to_string()))
                    .collect(),
            ),
        );
        m
    }

    #[test]
    fn test_unconditional_block() {
        let rules = vec![rule("Glob", "Use fd.")];
        let result = check_tool_block("Glob", &empty_input(), &rules);
        assert!(result.is_some());
        let json = serde_json::to_string(&result.unwrap().serialize(crate::models::Client::Claude))
            .unwrap();
        assert!(json.contains("deny"));
        assert!(json.contains("Use fd."));
    }

    #[test]
    fn test_no_match_passes() {
        let rules = vec![rule("Glob", "Use fd.")];
        let result = check_tool_block("Read", &empty_input(), &rules);
        assert!(result.is_none());
    }

    #[test]
    fn test_glob_pattern_match() {
        let rules = vec![rule("mcp__slack*", "Slack blocked.")];
        let result = check_tool_block("mcp__slack__post_message", &empty_input(), &rules);
        assert!(result.is_some());
    }

    #[test]
    fn test_domain_block_matching_url() {
        let rules = vec![domain_rule("*firecrawl*", "Use gh api.", &["github.com"])];
        let input = input_with_url("https://github.com/owner/repo");
        let result = check_tool_block("mcp__firecrawl__firecrawl_scrape", &input, &rules);
        assert!(result.is_some());
    }

    #[test]
    fn test_domain_block_non_matching_url() {
        let rules = vec![domain_rule("*firecrawl*", "Use gh api.", &["github.com"])];
        let input = input_with_url("https://example.com/page");
        let result = check_tool_block("mcp__firecrawl__firecrawl_scrape", &input, &rules);
        assert!(result.is_none());
    }

    #[test]
    fn test_domain_block_urls_array() {
        let rules = vec![domain_rule(
            "*firecrawl*",
            "blocked",
            &["raw.githubusercontent.com"],
        )];
        let input =
            input_with_urls(&["https://raw.githubusercontent.com/owner/repo/main/README.md"]);
        let result = check_tool_block("mcp__firecrawl__firecrawl_crawl", &input, &rules);
        assert!(result.is_some());
    }

    // === Default block rules exercised end-to-end ===
    //
    // These tests drive through Config::default() + check_tool_block so a
    // future edit to the default rule list can't silently stop matching the
    // tools we expect to cover.

    #[test]
    fn test_default_rules_block_firecrawl_api_github() {
        let rules = crate::config::Config::default().block_rules().to_vec();
        let input = input_with_url("https://api.github.com/repos/OWNER/REPO");
        let result = check_tool_block("mcp__firecrawl__firecrawl_scrape", &input, &rules);
        assert!(
            result.is_some(),
            "api.github.com via firecrawl should be denied"
        );
    }

    #[test]
    fn test_default_rules_block_firecrawl_gist_raw() {
        let rules = crate::config::Config::default().block_rules().to_vec();
        let input = input_with_url("https://gist.githubusercontent.com/OWNER/ID/raw/HASH/f");
        let result = check_tool_block("mcp__firecrawl__firecrawl_scrape", &input, &rules);
        assert!(
            result.is_some(),
            "raw gist content via firecrawl should be denied"
        );
    }

    #[test]
    fn test_default_rules_block_ref_read_url_github() {
        let rules = crate::config::Config::default().block_rules().to_vec();
        let input = input_with_url("https://raw.githubusercontent.com/OWNER/REPO/main/README.md");
        // Claude-style name
        let result_claude = check_tool_block("mcp__ref__ref_read_url", &input, &rules);
        assert!(
            result_claude.is_some(),
            "ref_read_url against github should be denied (Claude namespace)"
        );
        // Gemini-style name (single underscore)
        let result_gemini = check_tool_block("mcp_ref_ref_read_url", &input, &rules);
        assert!(
            result_gemini.is_some(),
            "ref_read_url against github should be denied (Gemini namespace)"
        );
    }

    #[test]
    fn test_default_rules_block_crawling_exa_github() {
        let rules = crate::config::Config::default().block_rules().to_vec();
        let input = input_with_url("https://github.com/OWNER/REPO/blob/main/src/lib.rs");
        let result = check_tool_block("mcp__exa__crawling_exa", &input, &rules);
        assert!(
            result.is_some(),
            "crawling_exa against github blob URL should be denied"
        );
    }

    #[test]
    fn test_default_rules_do_not_block_non_github_for_ref_and_exa() {
        let rules = crate::config::Config::default().block_rules().to_vec();
        let input = input_with_url("https://example.com/docs/page");
        assert!(check_tool_block("mcp__ref__ref_read_url", &input, &rules).is_none());
        assert!(check_tool_block("mcp__exa__crawling_exa", &input, &rules).is_none());
    }

    #[test]
    fn test_default_rules_do_not_block_unrelated_ref_and_exa_tools() {
        // Search-shaped tools in the same MCP namespaces should NOT be caught
        // even with a github URL (they don't take URLs as primary input).
        let rules = crate::config::Config::default().block_rules().to_vec();
        let input = input_with_url("https://raw.githubusercontent.com/OWNER/REPO/main/f");
        assert!(
            check_tool_block("mcp__ref__ref_search_documentation", &input, &rules).is_none(),
            "ref_search_documentation should not be caught by the ref_read_url rule"
        );
        assert!(
            check_tool_block("mcp__exa__web_search_exa", &input, &rules).is_none(),
            "web_search_exa should not be caught by the crawling_exa rule"
        );
    }

    #[test]
    fn test_domain_block_no_url_passes() {
        let rules = vec![domain_rule("*firecrawl*", "blocked", &["github.com"])];
        // Tool matches but no URL in input -> passes through
        let result = check_tool_block("mcp__firecrawl__firecrawl_scrape", &empty_input(), &rules);
        assert!(result.is_none());
    }

    #[test]
    fn test_multiple_rules_first_match_wins() {
        let rules = vec![rule("Glob", "First rule."), rule("Glob", "Second rule.")];
        let result = check_tool_block("Glob", &empty_input(), &rules);
        let json = serde_json::to_string(&result.unwrap().serialize(crate::models::Client::Claude))
            .unwrap();
        assert!(json.contains("First rule."));
    }

    #[test]
    fn test_empty_rules_passes_everything() {
        let rules: Vec<BlockRule> = vec![];
        assert!(check_tool_block("Glob", &empty_input(), &rules).is_none());
        assert!(check_tool_block("Grep", &empty_input(), &rules).is_none());
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("https://github.com/owner/repo"),
            Some("github.com")
        );
        assert_eq!(
            extract_domain("https://raw.githubusercontent.com/o/r/main/f"),
            Some("raw.githubusercontent.com")
        );
        assert_eq!(extract_domain("http://example.com"), Some("example.com"));
        assert_eq!(extract_domain("not-a-url"), None);
        assert_eq!(extract_domain(""), None);
    }

    #[test]
    fn test_extract_domain_with_port() {
        assert_eq!(
            extract_domain("https://github.com:443/owner/repo"),
            Some("github.com")
        );
        assert_eq!(
            extract_domain("http://example.com:8080/path"),
            Some("example.com")
        );
    }

    #[test]
    fn test_extract_domain_with_userinfo() {
        assert_eq!(
            extract_domain("https://user@github.com/repo"),
            Some("github.com")
        );
        assert_eq!(
            extract_domain("https://user:pass@github.com:443/repo"),
            Some("github.com")
        );
    }
}

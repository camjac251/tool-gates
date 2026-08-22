use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const AGENT_PLUGIN_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_json(relative: &str) -> Value {
    let path = repo_path(relative);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn split_skill(relative: &str) -> (String, String) {
    let path = repo_path(relative);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let without_open = text
        .strip_prefix("---\n")
        .unwrap_or_else(|| panic!("{} has no YAML frontmatter", path.display()));
    let (frontmatter, body) = without_open
        .split_once("\n---\n")
        .unwrap_or_else(|| panic!("{} has unterminated YAML frontmatter", path.display()));
    (frontmatter.to_owned(), body.to_owned())
}

#[test]
fn portable_manifest_stays_aligned_with_claude_metadata() {
    let portable = read_json("claude-plugin/plugin.json");
    let claude = read_json("claude-plugin/.claude-plugin/plugin.json");
    let marketplace = read_json(".claude-plugin/marketplace.json");
    let marketplace_plugin = &marketplace["plugins"][0];

    assert_eq!(portable["$schema"], AGENT_PLUGIN_SCHEMA);
    for field in ["name", "version", "description", "author"] {
        assert_eq!(
            portable[field], claude[field],
            "{field} differs between portable and Claude manifests"
        );
    }
    assert_eq!(portable["version"], marketplace_plugin["version"]);
    assert_eq!(claude["skills"], "./com.anthropic.claude-code/skills/");
}

#[test]
fn portable_and_claude_skill_bodies_stay_aligned() {
    for name in ["review", "test-gate"] {
        let (portable_frontmatter, portable_body) =
            split_skill(&format!("claude-plugin/skills/{name}/SKILL.md"));
        let (_, claude_body) = split_skill(&format!(
            "claude-plugin/com.anthropic.claude-code/skills/{name}/SKILL.md"
        ));

        assert!(
            portable_frontmatter.contains(&format!("name: {name}\n")),
            "portable {name} skill name is missing or mismatched"
        );
        for claude_field in ["argument-hint:", "disable-model-invocation:"] {
            assert!(
                !portable_frontmatter.contains(claude_field),
                "portable {name} skill contains Claude-only field {claude_field}"
            );
        }
        assert_eq!(
            portable_body, claude_body,
            "portable and Claude {name} skill instructions differ"
        );
    }
}

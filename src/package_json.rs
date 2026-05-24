//! Package.json script parsing and command extraction.
//!
//! Finds and parses package.json files to extract the underlying
//! shell commands from script definitions, enabling permission checks on
//! the actual commands that will run.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Subset of package.json we care about
#[derive(Debug, Deserialize, Default)]
pub struct PackageJson {
    #[serde(default)]
    pub scripts: HashMap<String, String>,
}

/// Find package.json starting from cwd and walking up
pub fn find_package_json(cwd: &str) -> Option<PathBuf> {
    let start = Path::new(cwd);
    let mut current = Some(start);

    while let Some(dir) = current {
        let path = dir.join("package.json");
        if path.exists() {
            return Some(path);
        }
        current = dir.parent();
    }
    None
}

/// Load and parse package.json
pub fn load_package_json(path: &Path) -> Option<PackageJson> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Extract the command for a script name
pub fn get_script_command(pkg: &PackageJson, script_name: &str) -> Option<String> {
    pkg.scripts.get(script_name).cloned()
}

/// True when the candidate names a file (has a `/` or code-file extension)
/// rather than a package.json script. `bun <file>` executes a file directly,
/// so it must not be looked up as a script (yields a spurious "Script not found").
fn looks_like_file_path(candidate: &str) -> bool {
    if candidate.contains('/') {
        return true;
    }
    // A dotted code-file extension (foo.ts, build.mjs) is a file, not a script.
    candidate.contains('.')
        && matches!(
            candidate.rsplit('.').next(),
            Some("ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "cts" | "mts")
        )
}

/// Check if a command is a package manager script invocation and extract the script name.
/// Returns (package_manager, script_name) if matched.
pub fn parse_script_invocation(command: &str) -> Option<(&'static str, String)> {
    let parts: Vec<&str> = command.split_whitespace().collect();

    if parts.is_empty() {
        return None;
    }

    match parts[0] {
        "npm" | "pnpm" | "yarn" | "bun" => {
            // npm run <script>, pnpm run <script>, yarn run <script>
            // Also: pnpm <script> (shorthand), yarn <script>, bun run <script>
            // Note: "exec" is NOT the same as "run" - exec runs arbitrary binaries, not scripts
            if parts.len() >= 3 && parts[1] == "run" {
                // `bun run <file>` executes a file, not a named script.
                if looks_like_file_path(parts[2]) {
                    return None;
                }
                let pm = match parts[0] {
                    "npm" => "npm",
                    "pnpm" => "pnpm",
                    "yarn" => "yarn",
                    "bun" => "bun",
                    _ => return None,
                };
                return Some((pm, parts[2].to_string()));
            }

            // Shorthand: pnpm <script> or yarn <script> (if not a built-in command)
            if parts.len() >= 2 {
                let builtin_commands = [
                    "add",
                    "remove",
                    "install",
                    "uninstall",
                    "update",
                    "upgrade",
                    "init",
                    "publish",
                    "pack",
                    "link",
                    "unlink",
                    "list",
                    "ls",
                    "outdated",
                    "audit",
                    "why",
                    "bin",
                    "cache",
                    "config",
                    "exec",
                    "dlx",
                    "create",
                    "store",
                    "rebuild",
                    "prune",
                    "dedupe",
                    "patch",
                    "licenses",
                    "doctor",
                    "completion",
                    "run",
                    "test",
                    "start",
                    "build",
                    "dev",
                    // Common scripts that are also TOML-allowed subcommands
                    // These should go through the gate, not script expansion
                    "lint",
                    "check",
                    "typecheck",
                    "format",
                    // Dev tools that can be invoked directly (pnpm biome, yarn vitest, etc.)
                    // Must match DEV_TOOLS in package_managers.rs
                    "biome",
                    "eslint",
                    "prettier",
                    "tsc",
                    "typescript",
                    "tsup",
                    "vite",
                    "vitest",
                    "jest",
                    "mocha",
                    "ava",
                    "esbuild",
                    "rollup",
                    "webpack",
                    "turbo",
                    "nx",
                    "stylelint",
                    "oxlint",
                    "knip",
                    "depcheck",
                    "madge",
                    "size-limit",
                    "markdownlint",
                    // Flags
                    "-v",
                    "--version",
                    "-h",
                    "--help",
                ];

                // If it's not a built-in, treat as script shorthand
                // But only for pnpm/yarn/bun (npm requires explicit "run")
                if parts[0] != "npm" && !builtin_commands.contains(&parts[1]) {
                    // `bun <file>` executes a file directly, not a named script.
                    if looks_like_file_path(parts[1]) {
                        return None;
                    }
                    let pm = match parts[0] {
                        "pnpm" => "pnpm",
                        "yarn" => "yarn",
                        "bun" => "bun",
                        _ => return None,
                    };
                    return Some((pm, parts[1].to_string()));
                }
            }
        }
        _ => {}
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_script_invocation_npm_run() {
        assert_eq!(
            parse_script_invocation("npm run lint"),
            Some(("npm", "lint".to_string()))
        );
        assert_eq!(
            parse_script_invocation("npm run build:prod"),
            Some(("npm", "build:prod".to_string()))
        );
    }

    #[test]
    fn test_parse_script_invocation_pnpm_run() {
        assert_eq!(
            parse_script_invocation("pnpm run test"),
            Some(("pnpm", "test".to_string()))
        );
    }

    #[test]
    fn test_parse_script_invocation_pnpm_shorthand() {
        // pnpm allows running scripts without "run" (for non-builtin script names)
        // Note: lint, check, typecheck, format, tsc are now treated as builtin commands
        // so they go through the gate path, not script expansion
        assert_eq!(
            parse_script_invocation("pnpm lint"),
            None // lint is now a builtin, goes through gate
        );
        assert_eq!(
            parse_script_invocation("pnpm typecheck"),
            None // typecheck is now a builtin
        );
        // Custom scripts are still expanded
        assert_eq!(
            parse_script_invocation("pnpm my-custom-script"),
            Some(("pnpm", "my-custom-script".to_string()))
        );
    }

    #[test]
    fn test_parse_script_invocation_builtin_not_script() {
        // These are built-in commands, not scripts
        assert_eq!(parse_script_invocation("pnpm install"), None);
        assert_eq!(parse_script_invocation("pnpm add lodash"), None);
        assert_eq!(parse_script_invocation("npm install"), None);
        assert_eq!(parse_script_invocation("yarn add lodash"), None);
    }

    #[test]
    fn test_parse_script_invocation_yarn() {
        assert_eq!(
            parse_script_invocation("yarn run test"),
            Some(("yarn", "test".to_string()))
        );
        // lint is now a builtin command, goes through gate
        assert_eq!(parse_script_invocation("yarn lint"), None);
        // Custom scripts are still expanded
        assert_eq!(
            parse_script_invocation("yarn my-custom-script"),
            Some(("yarn", "my-custom-script".to_string()))
        );
    }

    #[test]
    fn test_parse_script_invocation_bun() {
        assert_eq!(
            parse_script_invocation("bun run dev"),
            Some(("bun", "dev".to_string()))
        );
    }

    #[test]
    fn test_parse_script_invocation_bun_file_execution() {
        // `bun <file>` and `bun run <file>` execute a file, not a named script.
        assert_eq!(parse_script_invocation("bun src/main.ts"), None);
        assert_eq!(parse_script_invocation("bun run src/main.ts"), None);
        assert_eq!(parse_script_invocation("bun ./scripts/build.js"), None);
        assert_eq!(parse_script_invocation("bun run dist/app.mjs"), None);
        assert_eq!(parse_script_invocation("bun lib/entry.tsx"), None);
    }

    #[test]
    fn test_parse_script_invocation_script_names_with_dots_or_colons() {
        // Script names that are NOT files must still expand.
        assert_eq!(
            parse_script_invocation("bun run my-custom-script"),
            Some(("bun", "my-custom-script".to_string()))
        );
        assert_eq!(
            parse_script_invocation("pnpm build:prod"),
            Some(("pnpm", "build:prod".to_string()))
        );
    }

    #[test]
    fn test_looks_like_file_path() {
        assert!(looks_like_file_path("src/main.ts"));
        assert!(looks_like_file_path("./build.js"));
        assert!(looks_like_file_path("main.mjs"));
        assert!(looks_like_file_path("a/b"));
        // Script names, not files.
        assert!(!looks_like_file_path("lint"));
        assert!(!looks_like_file_path("my-custom-script"));
        assert!(!looks_like_file_path("build:prod"));
        // A bare extension word without a dotted name is not a file.
        assert!(!looks_like_file_path("js"));
    }

    #[test]
    fn test_parse_package_json() {
        let json = r#"{
            "name": "test-package",
            "scripts": {
                "lint": "eslint .",
                "build": "tsc && vite build",
                "test": "vitest run"
            }
        }"#;

        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        assert_eq!(pkg.scripts.get("lint"), Some(&"eslint .".to_string()));
        assert_eq!(
            pkg.scripts.get("build"),
            Some(&"tsc && vite build".to_string())
        );
    }

    #[test]
    fn test_get_script_command() {
        let json = r#"{"scripts": {"lint": "biome check .", "format": "biome format --write ."}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();

        assert_eq!(
            get_script_command(&pkg, "lint"),
            Some("biome check .".to_string())
        );
        assert_eq!(
            get_script_command(&pkg, "format"),
            Some("biome format --write .".to_string())
        );
        assert_eq!(get_script_command(&pkg, "nonexistent"), None);
    }
}

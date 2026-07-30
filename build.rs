//! Build script for tool-gates.
//!
//! Reads all rules/*.toml files and generates:
//! - src/generated/rules.rs - Rust code for declarative gates
//!
//! The rule-file deserialization types live in `src/rules_schema.rs` and are
//! shared with the library. The build script pulls them in directly with
//! `#[path = ...]` because it compiles before the lib crate exists, so it
//! cannot `use tool_gates::...`. That module's optional `schemars` derives are
//! gated on the `lib_only` cfg (set in `main()` for the lib/bin compile only),
//! so the build script never references the `schemars` crate, which lives under
//! `[dependencies]` and is not linkable from a build script.

#[path = "src/rules_schema.rs"]
mod rules_schema;

use rules_schema::*;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};

const GENERATED_FINGERPRINT_PREFIX: &str = "// tool-gates-generation-fingerprint: ";
const RUSTFMT_IDENTITY: &str = "rustfmt:edition-2024:v1";
const PRETTYPLEASE_IDENTITY: &str = "prettyplease:v1";

fn main() {
    // `lib_only` marks the library/binary compile so rules_schema.rs can gate
    // its `schemars`/JsonSchema references on it. Cargo propagates package
    // features into the build script too, but `schemars` is not a
    // build-dependency, so without this discriminator `--features schemars`
    // would fail to compile the build script's `#[path]` copy of the module.
    // This `rustc-cfg` applies to the lib/bin compile, not to the build
    // script's own compile, which is exactly the distinction we need. The cfg
    // name is registered package-wide via `[lints.rust]` in Cargo.toml.
    println!("cargo:rustc-cfg=lib_only");

    // Set git version info for --version flag
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/");

    // Get git version: tag if on tag, otherwise tag-commits-hash
    let git_version = Command::new("git")
        .args(["describe", "--tags", "--always"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_VERSION={}", git_version);

    // Rerun if any rule file changes
    println!("cargo:rerun-if-changed=rules/");

    let rules_dir = Path::new("rules");
    if !rules_dir.exists() {
        eprintln!("Warning: rules/ directory not found, skipping code generation");
        return;
    }

    // Skip code generation during cargo package --verify to avoid
    // "source directory was modified by build.rs" errors.
    // The generated files are committed to git and included in the package.
    //
    // During verify, CARGO_MANIFEST_DIR points to the extracted package
    // inside target/package/<name>-<version>/. OUT_DIR is unreliable here
    // because cargo reuses the workspace's target dir, not a nested one.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    if manifest_dir.contains("target/package/") {
        return;
    }

    // Watch each file individually for reliable rebuilds
    for entry in fs::read_dir(rules_dir)
        .expect("Failed to read rules directory")
        .flatten()
    {
        println!("cargo:rerun-if-changed={}", entry.path().display());
    }

    // Collect all rule files. `security.toml` is the raw-string floor, not a
    // per-program gate table, so it is parsed separately as a SecurityFloorFile
    // below and skipped here (it would fail RuleFile's deny_unknown_fields).
    let mut rule_files: Vec<(String, RuleFile)> = Vec::new();
    let mut security_floor: Option<(std::path::PathBuf, SecurityFloorFile)> = None;

    for entry in fs::read_dir(rules_dir).expect("Failed to read rules directory") {
        let entry = entry.expect("Failed to read directory entry");
        let path = entry.path();

        if path.extension().map(|e| e == "toml").unwrap_or(false) {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();

            let content = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));

            if name == "security" {
                let floor: SecurityFloorFile = toml::from_str(&content)
                    .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e));
                validate_security_floor(&path, &floor);
                security_floor = Some((path, floor));
                continue;
            }

            let rules: RuleFile = toml::from_str(&content)
                .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e));

            // Validate the rule file
            validate_rule_file(&path, &rules);

            rule_files.push((name, rules));
        }
    }

    // Sort by priority (lower = processed first), then by stable rule name.
    // `read_dir` order is unspecified, and several gates intentionally share
    // a priority, so priority alone would make generated output filesystem-
    // dependent.
    rule_files.sort_by(|a, b| {
        let pa = a.1.meta.priority.unwrap_or(100);
        let pb = b.1.meta.priority.unwrap_or(100);
        pa.cmp(&pb).then_with(|| a.0.cmp(&b.0))
    });

    // Generate Rust code
    let mut rust_code = generate_rust_code(&rule_files);

    // Append the raw-string security floor matcher, generated from
    // rules/security.toml (parsed separately above).
    if let Some((_, floor)) = &security_floor {
        rust_code.push_str(&generate_security_floor(floor));
    }

    // Write to src/generated/
    let out_dir = Path::new("src/generated");
    fs::create_dir_all(out_dir).expect("Failed to create src/generated directory");

    // Always write mod.rs to ensure it includes all generated modules
    let mod_content = r#"//! Auto-generated code from rules/*.toml files.
//!
//! DO NOT EDIT - changes will be overwritten by build.rs

pub mod rules;
"#;

    let rules_path = out_dir.join("rules.rs");
    let rustfmt_available = rustfmt_available();
    let preferred_fingerprint = generation_fingerprint(&rust_code, RUSTFMT_IDENTITY);
    let fallback_fingerprint = generation_fingerprint(&rust_code, PRETTYPLEASE_IDENTITY);
    let expected_fingerprint = if rustfmt_available {
        preferred_fingerprint
    } else {
        fallback_fingerprint
    };
    let existing_fingerprint = existing_generation_fingerprint(&rules_path);

    if existing_fingerprint != Some(expected_fingerprint) {
        // `--edition` must match Cargo.toml. Formatting through stdin keeps the
        // generated source off disk until it is complete.
        let (formatted, fingerprint) = if rustfmt_available {
            match format_with_rustfmt(&rust_code) {
                Some(formatted) => (formatted, preferred_fingerprint),
                None => (format_rust(&rust_code), fallback_fingerprint),
            }
        } else {
            (format_rust(&rust_code), fallback_fingerprint)
        };
        let content_fingerprint = generation_fingerprint(&formatted, "formatted-output");
        let generated = format!(
            "{GENERATED_FINGERPRINT_PREFIX}{fingerprint:016x}:{content_fingerprint:016x}\n{formatted}"
        );
        write_if_changed(&rules_path, generated.as_bytes()).expect("Failed to write rules.rs");
    }

    // mod.rs is fixed canonical text. Formatting it on every build-script run
    // is unnecessary; only write when its bytes actually differ.
    write_if_changed(&out_dir.join("mod.rs"), mod_content.as_bytes())
        .expect("Failed to write mod.rs");
}

// ============================================================================
// Validation
// ============================================================================

/// Maximum characters allowed in any `reason` field across rules/*.toml.
///
/// Reasons land in the agent's context as `permissionDecisionReason`. Keeping
/// them short forces help-menu style (verb-phrase + optional risk note) and
/// prevents verbose teaching prose from creeping back in. The 250-char cap
/// matches the style guide in AGENTS.md. Bump only after auditing the
/// audit's word-count math (see the prior token-cost audit).
const MAX_REASON_CHARS: usize = 250;

fn check_reason_length(file_name: &str, prog_name: &str, kind: &str, key: &str, reason: &str) {
    let len = reason.chars().count();
    if len > MAX_REASON_CHARS {
        panic!(
            "{}: {}: {} '{}' reason is {} chars (max {}). Trim to fit the help-menu style guide in AGENTS.md.\n  reason: {}",
            file_name, prog_name, kind, key, len, MAX_REASON_CHARS, reason
        );
    }
}

fn validate_rule_file(path: &Path, rules: &RuleFile) {
    let file_name = path.display().to_string();

    // Validate safe_commands
    for (i, cmd) in rules.safe_commands.iter().enumerate() {
        if cmd.trim().is_empty() {
            panic!("{}: safe_commands[{}] is empty", file_name, i);
        }
    }

    // Validate each program
    for program in &rules.programs {
        validate_program_rules(path, program);
    }

    // Validate conditional_allow
    for (i, rule) in rules.conditional_allow.iter().enumerate() {
        if rule.program.trim().is_empty() {
            panic!(
                "{}: conditional_allow[{}] has empty program name",
                file_name, i
            );
        }
    }

    // Validate command_groups (docs-only grid grouping). When present, the
    // groups must cover every safe_command exactly once and reference no
    // unknown command, so the generated grid never silently drops or
    // duplicates a command.
    if !rules.command_groups.is_empty() {
        use std::collections::HashSet;
        let safe: HashSet<&str> = rules.safe_commands.iter().map(String::as_str).collect();
        let mut seen: HashSet<&str> = HashSet::new();
        for group in &rules.command_groups {
            if group.title.trim().is_empty() {
                panic!(
                    "{}: command_groups has a group with an empty title",
                    file_name
                );
            }
            for cmd in &group.commands {
                if !safe.contains(cmd.as_str()) {
                    panic!(
                        "{}: command_groups: '{}' (in group '{}') is not a safe_command",
                        file_name, cmd, group.title
                    );
                }
                if !seen.insert(cmd.as_str()) {
                    panic!(
                        "{}: command_groups: '{}' appears in more than one group",
                        file_name, cmd
                    );
                }
            }
        }
        for cmd in &rules.safe_commands {
            if !seen.contains(cmd.as_str()) {
                panic!(
                    "{}: command_groups: safe_command '{}' is not in any group (grid would drop it)",
                    file_name, cmd
                );
            }
        }
    }
}

/// Validate `rules/security.toml`: unique ids, exactly one of regex/handler per
/// row, well-formed `within` rows, and the same 250-char reason cap the gates
/// enforce (Reason Style guide in AGENTS.md).
fn validate_security_floor(path: &Path, floor: &SecurityFloorFile) {
    let file_name = path.display().to_string();
    let mut seen_ids: HashSet<&str> = HashSet::new();

    for (i, p) in floor.patterns.iter().enumerate() {
        if p.id.trim().is_empty() {
            panic!("{}: patterns[{}] has an empty id", file_name, i);
        }
        if !seen_ids.insert(p.id.as_str()) {
            panic!("{}: duplicate pattern id '{}'", file_name, p.id);
        }

        // Exactly one matcher source.
        match (&p.regex, &p.handler) {
            (Some(_), Some(_)) => panic!(
                "{}: pattern '{}' sets both regex and handler (pick one)",
                file_name, p.id
            ),
            (None, None) => panic!(
                "{}: pattern '{}' sets neither regex nor handler",
                file_name, p.id
            ),
            _ => {}
        }

        // within-rows need a regex, a non-empty inner list, reason_args =
        // ["match"], and a {match} placeholder in the reason.
        if p.within.is_some() {
            if p.regex.is_none() {
                panic!(
                    "{}: pattern '{}' has `within` but no regex",
                    file_name, p.id
                );
            }
            if p.inner_contains_any.is_empty() {
                panic!(
                    "{}: pattern '{}' has `within` but empty inner_contains_any",
                    file_name, p.id
                );
            }
            if p.reason_args != ["match"] {
                panic!(
                    "{}: pattern '{}' `within` row must set reason_args = [\"match\"]",
                    file_name, p.id
                );
            }
            if !p.reason.contains("{match}") {
                panic!(
                    "{}: pattern '{}' `within` row reason must contain the {{match}} placeholder",
                    file_name, p.id
                );
            }
        } else {
            if !p.inner_contains_any.is_empty() {
                panic!(
                    "{}: pattern '{}' sets inner_contains_any without `within`",
                    file_name, p.id
                );
            }
            if !p.reason_args.is_empty() {
                panic!(
                    "{}: pattern '{}' sets reason_args without `within`",
                    file_name, p.id
                );
            }
        }

        check_reason_length(&file_name, "security-floor", "pattern", &p.id, &p.reason);
    }
}

fn validate_program_rules(path: &Path, program: &ProgramRules) {
    let file_name = path.display().to_string();
    let prog_name = &program.name;

    if prog_name.trim().is_empty() {
        panic!("{}: program has empty name", file_name);
    }

    // Track subcommands for conflict detection
    let mut allow_cmds: HashSet<String> = HashSet::new();
    let mut ask_cmds: HashSet<String> = HashSet::new();
    let mut block_cmds: HashSet<String> = HashSet::new();

    // Validate allow rules
    for (i, rule) in program.allow.iter().enumerate() {
        let parts = rule.subcommand_parts();
        // Allow rules with no subcommand are valid (they match the bare program)
        // Allow rules with only prefix are also valid
        if !parts.is_empty() {
            let key = parts.join(" ");
            if allow_cmds.contains(&key) {
                panic!(
                    "{}: {}: duplicate allow rule for '{}'",
                    file_name, prog_name, key
                );
            }
            allow_cmds.insert(key);
        } else if rule.subcommand_prefix.is_none()
            && rule.action_prefix.is_none()
            && rule.if_flags_any.is_empty()
        {
            // This is a bare allow rule with no conditions - it's valid
            if allow_cmds.contains("") {
                panic!("{}: {}: duplicate bare allow rule", file_name, prog_name);
            }
            allow_cmds.insert(String::new());
        }
        // Check for empty unless_flags entries
        for (j, flag) in rule.unless_flags.iter().enumerate() {
            if flag.trim().is_empty() {
                panic!(
                    "{}: {}: allow[{}].unless_flags[{}] is empty",
                    file_name, prog_name, i, j
                );
            }
        }
        // Allow reasons are documentation that also rides the runtime decision,
        // so hold them to the same length cap as ask/block reasons.
        if let Some(ref reason) = rule.reason {
            let key = if parts.is_empty() {
                format!("rule #{i}")
            } else {
                parts.join(" ")
            };
            check_reason_length(&file_name, prog_name, "allow", &key, reason);
        }
    }

    // Validate ask rules
    let mut has_bare_ask = false;
    for (i, rule) in program.ask.iter().enumerate() {
        let parts = rule.subcommand_parts();

        // Reason is required
        if rule.reason.trim().is_empty() {
            let subcmd = if !parts.is_empty() {
                parts.join(" ")
            } else {
                format!("rule #{}", i)
            };
            panic!(
                "{}: {}: ask '{}' has empty reason",
                file_name, prog_name, subcmd
            );
        }
        let key = if !parts.is_empty() {
            parts.join(" ")
        } else {
            format!("rule #{}", i)
        };
        check_reason_length(&file_name, prog_name, "ask", &key, &rule.reason);

        // Track bare ask rules (no subcommand, no prefix, no flags - matches any invocation)
        if parts.is_empty()
            && rule.subcommand_prefix.is_none()
            && rule.action_prefix.is_none()
            && rule.if_flags_any.is_empty()
        {
            if has_bare_ask {
                panic!("{}: {}: duplicate bare ask rule", file_name, prog_name);
            }
            has_bare_ask = true;
            continue; // Bare ask is valid - it matches the program itself
        }

        // Only check for duplicates on simple asks (no flags or prefix)
        // Flagged/prefixed asks can have the same subcommand as they have different conditions
        if !parts.is_empty()
            && rule.if_flags_any.is_empty()
            && rule.subcommand_prefix.is_none()
            && rule.action_prefix.is_none()
        {
            let key = parts.join(" ");
            if ask_cmds.contains(&key) {
                panic!(
                    "{}: {}: duplicate ask rule for '{}'",
                    file_name, prog_name, key
                );
            }
            ask_cmds.insert(key);
        }
    }

    // Validate block rules
    let mut has_bare_block = false;
    for (i, rule) in program.block.iter().enumerate() {
        let parts = rule.subcommand_parts();

        // Track bare block rules (matches any invocation of the program)
        if parts.is_empty() && rule.subcommand_prefix.is_none() {
            if has_bare_block {
                panic!("{}: {}: duplicate bare block rule", file_name, prog_name);
            }
            has_bare_block = true;
            // Bare block is valid - it matches the program itself (e.g., shutdown)
        }

        let key = if !parts.is_empty() {
            parts.join(" ")
        } else if let Some(ref prefix) = rule.subcommand_prefix {
            format!("{}*", prefix)
        } else {
            format!("rule #{}", i)
        };
        if rule.reason.trim().is_empty() {
            panic!(
                "{}: {}: block '{}' has empty reason",
                file_name, prog_name, key
            );
        }
        check_reason_length(&file_name, prog_name, "block", &key, &rule.reason);

        // Track for duplicate/conflict detection (only for rules with subcommand, not prefix-only)
        if !parts.is_empty() {
            let key = parts.join(" ");
            if block_cmds.contains(&key) {
                panic!(
                    "{}: {}: duplicate block rule for '{}'",
                    file_name, prog_name, key
                );
            }
            block_cmds.insert(key.clone());

            // Check for conflicts with allow rules
            if allow_cmds.contains(&key) {
                panic!(
                    "{}: {}: conflicting rules - '{}' is in both allow and block",
                    file_name, prog_name, key
                );
            }
        }
    }
}

// ============================================================================
// Rust Code Generation
// ============================================================================

fn generate_rust_code(rule_files: &[(String, RuleFile)]) -> String {
    let mut output = String::new();

    // Header
    output.push_str("//! Auto-generated from rules/*.toml files.\n");
    output.push_str("//! DO NOT EDIT - changes will be overwritten by build.rs\n\n");

    output.push_str("#![allow(dead_code)]\n");
    output.push_str("#![allow(clippy::too_many_lines)]\n");
    output.push_str("#![allow(clippy::nonminimal_bool)]\n\n");

    output.push_str("use crate::models::{CommandInfo, GateResult};\n");
    output.push_str("use std::collections::{HashMap, HashSet};\n");
    output.push_str("use std::sync::LazyLock;\n\n");

    // Collect all safe commands
    let mut all_safe_commands: Vec<&str> = Vec::new();
    for (_, rules) in rule_files {
        for cmd in &rules.safe_commands {
            all_safe_commands.push(cmd);
        }
    }
    all_safe_commands.sort();
    all_safe_commands.dedup();

    if !all_safe_commands.is_empty() {
        output.push_str(&generate_safe_commands(&all_safe_commands));
        output.push('\n');
    }

    // Antigravity native allowlist source: the programs tool-gates allows
    // unconditionally, emitted by `tool-gates agy allowlist`.
    output.push_str(&generate_antigravity_allow_commands(rule_files));
    output.push('\n');

    // Collect all conditional allows
    let mut all_conditionals: Vec<&ConditionalRule> = Vec::new();
    for (_, rules) in rule_files {
        for cond in &rules.conditional_allow {
            all_conditionals.push(cond);
        }
    }

    if !all_conditionals.is_empty() {
        output.push_str(&generate_conditional_rules(&all_conditionals));
        output.push('\n');
    }

    // Generate per-program rules
    for (name, rules) in rule_files {
        for program in &rules.programs {
            output.push_str(&generate_program_rules(name, program));
            output.push('\n');
        }
    }

    // Generate master check function
    output.push_str(&generate_master_check(rule_files));

    // Generate unified gate functions
    output.push_str(&generate_gate_functions(rule_files));

    // Generate file-editing detection code
    output.push_str(&generate_file_editing_code(rule_files));

    output
}

fn generate_safe_commands(commands: &[&str]) -> String {
    let mut output = String::new();

    output.push_str("/// Safe commands that are always allowed\n");
    output.push_str("pub static SAFE_COMMANDS: LazyLock<HashSet<&str>> = LazyLock::new(|| {\n");
    output.push_str("    [\n");

    for cmd in commands {
        output.push_str(&format!("        \"{}\",\n", escape_rust_string(cmd)));
    }

    output.push_str("    ].into_iter().collect()\n");
    output.push_str("});\n\n");

    output.push_str("/// Check if a command is in the safe commands list\n");
    output.push_str("pub fn check_safe_command(cmd: &CommandInfo) -> Option<GateResult> {\n");
    output.push_str("    // Strip path prefix to handle /usr/bin/cat etc.\n");
    output.push_str("    let program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);\n");
    output.push_str("    if SAFE_COMMANDS.contains(program) {\n");
    output.push_str("        Some(GateResult::allow())\n");
    output.push_str("    } else {\n");
    output.push_str("        None\n");
    output.push_str("    }\n");
    output.push_str("}\n");

    output
}

/// Generate `ANTIGRAVITY_ALLOW_COMMANDS`: the programs tool-gates allows
/// unconditionally (read-only, no dangerous flags or args), used by
/// `tool-gates agy allowlist` to emit Antigravity native `command(<prog>)` allow
/// rules. agy resolves a tool call as the strictest of its candidate decisions,
/// so a native allow here removes the default Ask for these commands while the
/// tool-gates hook still tightens (deny/ask/force_ask) over any dangerous form.
fn generate_antigravity_allow_commands(rule_files: &[(String, RuleFile)]) -> String {
    // Shell builtins / keywords that appear in safe_commands but are not real
    // binaries. A `command(<builtin>)` agy rule is meaningless, so drop them.
    const SHELL_BUILTINS: &[&str] = &[
        "[",
        "[[",
        "]]",
        "test",
        ":",
        ".",
        "cd",
        "set",
        "unset",
        "export",
        "readonly",
        "local",
        "declare",
        "typeset",
        "eval",
        "source",
        "exec",
        "trap",
        "shift",
        "getopts",
        "read",
        "wait",
        "jobs",
        "fg",
        "bg",
        "pushd",
        "popd",
        "dirs",
        "alias",
        "unalias",
        "let",
        "times",
        "umask",
        "ulimit",
        "type",
        "hash",
        "help",
        "history",
        "fc",
        "bind",
        "caller",
        "enable",
        "logout",
        "mapfile",
        "readarray",
        "suspend",
        "compgen",
        "complete",
        "compopt",
        "true",
        "false",
        "return",
        "break",
        "continue",
        "exit",
        // zsh/ksh echo equivalent. A same-named binary exists on some systems,
        // so keep it out of the native allowlists even though the gate engine
        // treats it as safe.
        "print",
    ];

    // Exclusions: programs that are conditionally gated anywhere (any ask/block
    // rule), wrap a custom handler, or carry API-method rules must never be
    // blanket-allowed natively. Collecting across all gates catches a program
    // listed as safe in one file but conditional in another (e.g. `yq`, safe in
    // basics, ask-on-`-i` in devtools). Custom handlers catch the interpreter
    // entries (`bash`/`sh`/`zsh`/`xargs`/`command`); api_rules catches `curl`.
    let mut excluded: HashSet<&str> = HashSet::new();
    for builtin in SHELL_BUILTINS {
        excluded.insert(*builtin);
    }
    for (_, rules) in rule_files {
        for handler in &rules.custom_handlers {
            excluded.insert(handler.program.as_str());
        }
        for program in &rules.programs {
            let conditional =
                !program.ask.is_empty() || !program.block.is_empty() || program.api_rules.is_some();
            if conditional {
                excluded.insert(program.name.as_str());
                for alias in &program.aliases {
                    excluded.insert(alias.as_str());
                }
            }
        }
    }

    // Candidates: every safe_command, plus every program that is unconditionally
    // allowed (unknown_action = allow with no allow/ask/block/api rules).
    let mut candidates: Vec<&str> = Vec::new();
    for (_, rules) in rule_files {
        for cmd in &rules.safe_commands {
            candidates.push(cmd);
        }
        for program in &rules.programs {
            let unconditional = program.unknown_action == UnknownAction::Allow
                && program.allow.is_empty()
                && program.ask.is_empty()
                && program.block.is_empty()
                && program.api_rules.is_none();
            if unconditional {
                candidates.push(program.name.as_str());
                for alias in &program.aliases {
                    candidates.push(alias.as_str());
                }
            }
        }
    }

    let mut allow: Vec<&str> = candidates
        .into_iter()
        .filter(|c| !excluded.contains(c))
        .collect();
    allow.sort_unstable();
    allow.dedup();

    let mut output = String::new();
    output.push_str(
        "/// Programs tool-gates allows unconditionally, emitted as Antigravity\n\
         /// native `command(<prog>)` allow rules by `tool-gates agy allowlist`.\n",
    );
    output.push_str("pub static ANTIGRAVITY_ALLOW_COMMANDS: &[&str] = &[\n");
    for cmd in &allow {
        output.push_str(&format!("    \"{}\",\n", escape_rust_string(cmd)));
    }
    output.push_str("];\n");

    output
}

fn generate_conditional_rules(rules: &[&ConditionalRule]) -> String {
    let mut output = String::new();

    output.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
    output.push_str("pub enum ConditionalAction {\n");
    output.push_str("    Skip,\n");
    output.push_str("    Ask,\n");
    output.push_str("    Block,\n");
    output.push_str("}\n\n");

    output
        .push_str("/// Conditional allow rules (program -> (flags that prevent allow, action))\n");
    output.push_str(
        "pub static CONDITIONAL_ALLOW: LazyLock<HashMap<&str, (&[&str], ConditionalAction)>> = LazyLock::new(|| {\n",
    );
    output.push_str("    [\n");

    for rule in rules {
        let flags: Vec<String> = rule
            .unless_flags
            .iter()
            .map(|f| format!("\"{}\"", escape_rust_string(f)))
            .collect();
        let action = match rule.on_flag_present {
            OnFlagAction::Skip => "ConditionalAction::Skip",
            OnFlagAction::Ask => "ConditionalAction::Ask",
            OnFlagAction::Block => "ConditionalAction::Block",
        };
        output.push_str(&format!(
            "        (\"{}\", (&[{}] as &[&str], {})),\n",
            escape_rust_string(&rule.program),
            flags.join(", "),
            action
        ));
        for alias in &rule.aliases {
            output.push_str(&format!(
                "        (\"{}\", (&[{}] as &[&str], {})),\n",
                escape_rust_string(alias),
                flags.join(", "),
                action
            ));
        }
    }

    output.push_str("    ].into_iter().collect()\n");
    output.push_str("});\n\n");

    output.push_str("/// Check conditional allow rules\n");
    output.push_str("pub fn check_conditional_allow(cmd: &CommandInfo) -> Option<GateResult> {\n");
    output.push_str("    // Strip path prefix to handle /usr/bin/sed etc.\n");
    output.push_str("    let program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);\n");
    output.push_str("    if let Some((flags, action)) = CONDITIONAL_ALLOW.get(program) {\n");
    output.push_str(
        "        let has_flag = cmd.args.iter().any(|arg| flags.contains(&arg.as_str()));\n",
    );
    output.push_str("        if has_flag {\n");
    output.push_str("            match action {\n");
    output.push_str("                ConditionalAction::Skip => None,\n");
    output.push_str("                ConditionalAction::Ask => Some(GateResult::ask(format!(\"{}: in-place edit\", cmd.program))),\n");
    output.push_str("                ConditionalAction::Block => Some(GateResult::block(format!(\"{}: blocked\", cmd.program))),\n");
    output.push_str("            }\n");
    output.push_str("        } else {\n");
    output.push_str("            Some(GateResult::allow())\n");
    output.push_str("        }\n");
    output.push_str("    } else {\n");
    output.push_str("        None\n");
    output.push_str("    }\n");
    output.push_str("}\n");

    output
}

/// True when this ask must stay an explicit prompt under Claude Code auto mode.
///
/// Claude Code hands a hook `ask` straight back to the user without consulting
/// the auto-mode classifier, so `auto = "prompt"` is how a rule opts out of
/// classifier adjudication.
fn holds_in_auto(ask: &AskRule) -> bool {
    ask.auto == AutoDisposition::Prompt
}

/// Method-call suffix appended to a generated `GateResult::ask(..)`.
fn auto_hold_suffix(ask: &AskRule) -> &'static str {
    if holds_in_auto(ask) {
        ".hold_in_auto()"
    } else {
        ""
    }
}

fn generate_program_rules(file_name: &str, program: &ProgramRules) -> String {
    let mut output = String::new();
    let name = &program.name;
    let name_upper = name.to_uppercase().replace('-', "_");
    let fn_name = name.replace('-', "_");

    output.push_str(&format!(
        "// === {} (from {}.toml) ===\n\n",
        name.to_uppercase(),
        file_name
    ));

    // Collect simple allows (no conditions, no reason)
    let simple_allows: Vec<String> = program
        .allow
        .iter()
        .filter(|r| {
            r.subcommand_prefix.is_none()
                && r.action_prefix.is_none()
                && r.unless_flags.is_empty()
                && r.unless_args_contain.is_empty()
                && r.if_flags_any.is_empty()
                && r.reason.is_none() // Allows with reasons go to complex path
        })
        .map(|r| r.subcommand_parts().join(" "))
        .filter(|s| !s.is_empty())
        .collect();

    // Collect simple asks (with subcommand)
    let simple_asks: Vec<(String, String, bool)> = program
        .ask
        .iter()
        .filter(|r| {
            r.subcommand_prefix.is_none()
                && r.action_prefix.is_none()
                && r.if_flags.is_empty()
                && r.if_flags_any.is_empty()
        })
        .map(|r| {
            (
                r.subcommand_parts().join(" "),
                r.reason.clone(),
                holds_in_auto(r),
            )
        })
        .filter(|(s, _, _)| !s.is_empty())
        .collect();

    // Find bare ask rule (matches any invocation of the program)
    let bare_ask: Option<&AskRule> = program.ask.iter().find(|r| {
        r.subcommand_parts().is_empty()
            && r.subcommand_prefix.is_none()
            && r.action_prefix.is_none()
            && r.if_flags_any.is_empty()
    });

    // Collect simple blocks
    let simple_blocks: Vec<(String, String)> = program
        .block
        .iter()
        .filter(|r| r.if_args_contain.is_empty())
        .map(|r| (r.subcommand_parts().join(" "), r.reason.clone()))
        .filter(|(s, _)| !s.is_empty())
        .collect();

    // Collect complex blocks (with if_args_contain or subcommand_prefix)
    let complex_blocks: Vec<&BlockRule> = program
        .block
        .iter()
        .filter(|r| !r.if_args_contain.is_empty() || r.subcommand_prefix.is_some())
        .collect();

    // Find bare block rule (matches any invocation of the program)
    let bare_block: Option<&BlockRule> = program.block.iter().find(|r| {
        r.subcommand_parts().is_empty()
            && r.subcommand_prefix.is_none()
            && r.if_args_contain.is_empty()
    });

    // Generate statics
    if !simple_allows.is_empty() {
        output.push_str(&format!(
            "pub static {}_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {{\n",
            name_upper
        ));
        output.push_str("    [\n");
        for subcmd in &simple_allows {
            output.push_str(&format!("        \"{}\",\n", escape_rust_string(subcmd)));
        }
        output.push_str("    ].into_iter().collect()\n");
        output.push_str("});\n\n");
    }

    if !simple_asks.is_empty() {
        output.push_str(&format!(
            "pub static {}_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {{\n",
            name_upper
        ));
        output.push_str("    [\n");
        for (subcmd, reason, _) in &simple_asks {
            output.push_str(&format!(
                "        (\"{}\", \"{}\"),\n",
                escape_rust_string(subcmd),
                escape_rust_string(reason)
            ));
        }
        output.push_str("    ].into_iter().collect()\n");
        output.push_str("});\n\n");

        // Subcommands whose ask must survive auto mode instead of deferring
        // to the classifier.
        if simple_asks.iter().any(|(_, _, hold)| *hold) {
            output.push_str(&format!(
                "pub static {}_ASK_HOLD: LazyLock<HashSet<&str>> = LazyLock::new(|| {{\n",
                name_upper
            ));
            output.push_str("    [\n");
            for (subcmd, _, _) in simple_asks.iter().filter(|(_, _, hold)| *hold) {
                output.push_str(&format!("        \"{}\",\n", escape_rust_string(subcmd)));
            }
            output.push_str("    ].into_iter().collect()\n");
            output.push_str("});\n\n");
        }
    }

    if !simple_blocks.is_empty() {
        output.push_str(&format!(
            "pub static {}_BLOCK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {{\n",
            name_upper
        ));
        output.push_str("    [\n");
        for (subcmd, reason) in &simple_blocks {
            output.push_str(&format!(
                "        (\"{}\", \"{}\"),\n",
                escape_rust_string(subcmd),
                escape_rust_string(reason)
            ));
        }
        output.push_str("    ].into_iter().collect()\n");
        output.push_str("});\n\n");
    }

    // Generate check function
    output.push_str(&format!("/// Check {} commands declaratively\n", name));
    output.push_str(&format!(
        "pub fn check_{}_declarative(cmd: &CommandInfo) -> Option<GateResult> {{\n",
        fn_name
    ));

    // Check program name and aliases
    let mut programs = vec![format!("\"{}\"", name)];
    for alias in &program.aliases {
        programs.push(format!("\"{}\"", alias));
    }
    output.push_str(&format!(
        "    if ![{}].contains(&cmd.program.as_str()) {{\n",
        programs.join(", ")
    ));
    output.push_str("        return None;\n");
    output.push_str("    }\n\n");

    // Check allow_if_flags first
    if !program.allow_if_flags.is_empty() {
        output.push_str("    // Check allow_if_flags (e.g., --dry-run)\n");
        for flag_override in &program.allow_if_flags {
            let flags: Vec<String> = flag_override
                .flags_any
                .iter()
                .map(|f| format!("\"{}\"", escape_rust_string(f)))
                .collect();
            output.push_str(&format!(
                "    if cmd.args.iter().any(|a| [{}].contains(&a.as_str())) {{\n",
                flags.join(", ")
            ));
            output.push_str("        return Some(GateResult::allow());\n");
            output.push_str("    }\n");
        }
        output.push('\n');
    }

    // Handle bare block rule (blocks any invocation of the program)
    if let Some(block) = bare_block {
        output.push_str(&format!(
            "    // Bare block rule - any {} invocation is blocked\n",
            name
        ));
        output.push_str(&format!(
            "    Some(GateResult::block(\"{}: {}\"))\n",
            name,
            escape_rust_string(&block.reason)
        ));
        output.push_str("}\n");
        return output; // Skip all subcommand matching code
    }

    // Get subcommand for matching
    output.push_str("    #[allow(unused_variables)]\n");
    output.push_str("    let subcmd = if cmd.args.is_empty() {\n");
    output.push_str("        String::new()\n");
    output.push_str("    } else if cmd.args.len() == 1 {\n");
    output.push_str("        cmd.args[0].clone()\n");
    output.push_str("    } else {\n");
    output.push_str("        format!(\"{} {}\", cmd.args[0], cmd.args[1])\n");
    output.push_str("    };\n");
    output.push_str("    #[allow(unused_variables)]\n");
    output.push_str(
        "    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or(\"\");\n",
    );
    // Three-word key. Rules like `gcloud container clusters delete` are keyed on
    // their full path, so without this the map lookups can only ever see the
    // first two words and every such rule is dead.
    output.push_str("    #[allow(unused_variables)]\n");
    output.push_str("    let subcmd_triple = if cmd.args.len() >= 3 {\n");
    output.push_str("        format!(\"{} {} {}\", cmd.args[0], cmd.args[1], cmd.args[2])\n");
    output.push_str("    } else {\n");
    output.push_str("        String::new()\n");
    output.push_str("    };\n\n");

    // Check blocks first (highest priority)
    if !simple_blocks.is_empty() {
        output.push_str(&format!(
            "    if let Some(reason) = {}_BLOCK.get(subcmd_triple.as_str()).or_else(|| {}_BLOCK.get(subcmd.as_str())) {{\n",
            name_upper, name_upper
        ));
        output.push_str(&format!(
            "        return Some(GateResult::block(format!(\"{}: {{}}\", reason)));\n",
            name
        ));
        output.push_str("    }\n\n");
    }

    // Check complex blocks (with if_args_contain or subcommand_prefix)
    if !complex_blocks.is_empty() {
        output.push_str("    // Check conditional block rules\n");
        for block in &complex_blocks {
            let parts = block.subcommand_parts();

            // Handle subcommand_prefix blocks
            if let Some(ref prefix) = block.subcommand_prefix {
                if parts.is_empty() {
                    // Use subcmd for multi-word prefixes, subcmd_single for single-word
                    let var = if prefix.contains(' ') {
                        "subcmd"
                    } else {
                        "subcmd_single"
                    };
                    output.push_str(&format!(
                        "    if {}.starts_with(\"{}\") {{\n",
                        var,
                        escape_rust_string(prefix)
                    ));
                } else {
                    let check = generate_subcommand_match(&parts);
                    output.push_str(&format!(
                        "    if {} && cmd.args.get({}).is_some_and(|a| a.starts_with(\"{}\")) {{\n",
                        check,
                        parts.len(),
                        escape_rust_string(prefix)
                    ));
                }
                output.push_str(&format!(
                    "        return Some(GateResult::block(\"{}: {}\"));\n",
                    name,
                    escape_rust_string(&block.reason)
                ));
                output.push_str("    }\n");
                continue;
            }

            // Handle if_args_contain blocks
            if parts.is_empty() {
                continue;
            }
            let subcmd_check = generate_subcommand_match(&parts);
            let args_checks: Vec<String> = block
                .if_args_contain
                .iter()
                .map(|a| {
                    format!(
                        "cmd.args.iter().any(|x| x == \"{}\")",
                        escape_rust_string(a)
                    )
                })
                .collect();
            output.push_str(&format!(
                "    if {} && ({}) {{\n",
                subcmd_check,
                args_checks.join(" || ")
            ));
            output.push_str(&format!(
                "        return Some(GateResult::block(\"{}: {}\"));\n",
                name,
                escape_rust_string(&block.reason)
            ));
            output.push_str("    }\n");
        }
        output.push('\n');
    }

    // Check complex asks (with flags or prefixes)
    let complex_asks: Vec<&AskRule> = program
        .ask
        .iter()
        .filter(|r| {
            !r.if_flags_any.is_empty() || r.subcommand_prefix.is_some() || r.action_prefix.is_some()
        })
        .collect();

    if !complex_asks.is_empty() {
        output.push_str("    // Check ask rules with flag/prefix conditions\n");
        for ask in complex_asks {
            if !ask.if_flags_any.is_empty() {
                let parts = ask.subcommand_parts();
                let subcmd_check = if parts.is_empty() {
                    "true".to_string()
                } else {
                    generate_subcommand_match(&parts)
                };
                let flags: Vec<String> = ask
                    .if_flags_any
                    .iter()
                    .map(|f| format!("\"{}\"", escape_rust_string(f)))
                    .collect();
                output.push_str(&format!(
                    "    if {} && cmd.args.iter().any(|a| [{}].contains(&a.as_str())) {{\n",
                    subcmd_check,
                    flags.join(", ")
                ));
                output.push_str(&format!(
                    "        return Some(GateResult::ask(\"{}\"){});\n",
                    escape_rust_string(&ask.reason),
                    auto_hold_suffix(ask)
                ));
                output.push_str("    }\n");
            }
            // Handle subcommand_prefix for ask rules
            if let Some(ref prefix) = ask.subcommand_prefix {
                let parts = ask.subcommand_parts();
                if parts.is_empty() {
                    // Use subcmd for multi-word prefixes, subcmd_single for single-word
                    let var = if prefix.contains(' ') {
                        "subcmd"
                    } else {
                        "subcmd_single"
                    };
                    output.push_str(&format!(
                        "    if {}.starts_with(\"{}\") {{\n",
                        var,
                        escape_rust_string(prefix)
                    ));
                } else {
                    let check = generate_subcommand_match(&parts);
                    output.push_str(&format!(
                        "    if {} && cmd.args.get({}).is_some_and(|a| a.starts_with(\"{}\")) {{\n",
                        check,
                        parts.len(),
                        escape_rust_string(prefix)
                    ));
                }
                output.push_str(&format!(
                    "        return Some(GateResult::ask(\"{}: {}\"){});\n",
                    name,
                    escape_rust_string(&ask.reason),
                    auto_hold_suffix(ask)
                ));
                output.push_str("    }\n");
            }
            // Handle action_prefix - checks if args[1] starts with prefix
            // Useful for AWS-style commands: aws <service> <action>
            if let Some(ref prefix) = ask.action_prefix {
                output.push_str(&format!(
                    "    if cmd.args.get(1).is_some_and(|a| a.starts_with(\"{}\")) {{\n",
                    escape_rust_string(prefix)
                ));
                output.push_str(&format!(
                    "        return Some(GateResult::ask(\"{}: {}\"){});\n",
                    name,
                    escape_rust_string(&ask.reason),
                    auto_hold_suffix(ask)
                ));
                output.push_str("    }\n");
            }
        }
        output.push('\n');
    }

    // Check simple allows
    if !simple_allows.is_empty() {
        output.push_str(&format!(
            "    if {}_ALLOW.contains(subcmd_triple.as_str()) || {}_ALLOW.contains(subcmd.as_str()) || {}_ALLOW.contains(subcmd_single) {{\n",
            name_upper, name_upper, name_upper
        ));
        output.push_str("        return Some(GateResult::allow());\n");
        output.push_str("    }\n\n");
    }

    // Check complex allows (with conditions)
    let complex_allows: Vec<&AllowRule> = program
        .allow
        .iter()
        .filter(|r| {
            r.subcommand_prefix.is_some()
                || r.action_prefix.is_some()
                || !r.unless_flags.is_empty()
                || !r.if_flags_any.is_empty()
                || r.reason.is_some() // Allows with reasons need special handling
        })
        .collect();

    if !complex_allows.is_empty() {
        output.push_str("    // Check conditional allow rules\n");
        for allow in complex_allows {
            let parts = allow.subcommand_parts();

            let allow_call = generate_allow_call(&allow.reason);

            if let Some(ref prefix) = allow.subcommand_prefix {
                if parts.is_empty() {
                    // Use subcmd for multi-word prefixes, subcmd_single for single-word
                    let var = if prefix.contains(' ') {
                        "subcmd"
                    } else {
                        "subcmd_single"
                    };
                    output.push_str(&format!(
                        "    if {}.starts_with(\"{}\") {{\n",
                        var,
                        escape_rust_string(prefix)
                    ));
                } else {
                    let check = generate_subcommand_match(&parts);
                    output.push_str(&format!(
                        "    if {} && cmd.args.get({}).is_some_and(|a| a.starts_with(\"{}\")) {{\n",
                        check,
                        parts.len(),
                        escape_rust_string(prefix)
                    ));
                }
                output.push_str(&format!("        return {};\n", allow_call));
                output.push_str("    }\n");
            }

            // Handle action_prefix - checks if args[1] starts with prefix
            // Useful for AWS-style commands: aws <service> <action>
            if let Some(ref prefix) = allow.action_prefix {
                output.push_str(&format!(
                    "    if cmd.args.get(1).is_some_and(|a| a.starts_with(\"{}\")) {{\n",
                    escape_rust_string(prefix)
                ));
                output.push_str(&format!("        return {};\n", allow_call));
                output.push_str("    }\n");
            }

            if !allow.unless_flags.is_empty() && !parts.is_empty() {
                let check = generate_subcommand_match(&parts);
                let flags: Vec<String> = allow
                    .unless_flags
                    .iter()
                    .map(|f| format!("\"{}\"", escape_rust_string(f)))
                    .collect();
                output.push_str(&format!(
                    "    if {} && !cmd.args.iter().any(|a| [{}].contains(&a.as_str())) {{\n",
                    check,
                    flags.join(", ")
                ));
                output.push_str(&format!("        return {};\n", allow_call));
                output.push_str("    }\n");
            }

            // Handle if_flags_any (allow if any of these flags present)
            if !allow.if_flags_any.is_empty() {
                let flags: Vec<String> = allow
                    .if_flags_any
                    .iter()
                    .map(|f| format!("\"{}\"", escape_rust_string(f)))
                    .collect();
                // Include subcommand check if subcommand is specified
                let subcmd_check = if parts.is_empty() {
                    "true".to_string()
                } else {
                    generate_subcommand_match(&parts)
                };
                output.push_str(&format!(
                    "    if {} && cmd.args.iter().any(|a| [{}].contains(&a.as_str())) {{\n",
                    subcmd_check,
                    flags.join(", ")
                ));
                output.push_str(&format!("        return {};\n", allow_call));
                output.push_str("    }\n");
            }

            // Handle allows with just a reason (simple subcommand match with custom reason)
            if allow.reason.is_some()
                && allow.subcommand_prefix.is_none()
                && allow.action_prefix.is_none()
                && allow.unless_flags.is_empty()
                && allow.if_flags_any.is_empty()
                && !parts.is_empty()
            {
                let check = generate_subcommand_match(&parts);
                output.push_str(&format!("    if {} {{\n", check));
                output.push_str(&format!("        return {};\n", allow_call));
                output.push_str("    }\n");
            }
        }
        output.push('\n');
    }

    // Check simple asks
    if !simple_asks.is_empty() {
        output.push_str(&format!(
            "    if let Some(reason) = {}_ASK.get(subcmd_triple.as_str()).or_else(|| {}_ASK.get(subcmd.as_str())).or_else(|| {}_ASK.get(subcmd_single)) {{\n",
            name_upper, name_upper, name_upper
        ));
        if simple_asks.iter().any(|(_, _, hold)| *hold) {
            output.push_str(&format!(
                "        let result = GateResult::ask(format!(\"{}: {{}}\", reason));\n",
                name
            ));
            output.push_str(&format!(
                "        if {}_ASK_HOLD.contains(subcmd_triple.as_str()) || {}_ASK_HOLD.contains(subcmd.as_str()) || {}_ASK_HOLD.contains(subcmd_single) {{\n",
                name_upper, name_upper, name_upper
            ));
            output.push_str("            return Some(result.hold_in_auto());\n");
            output.push_str("        }\n");
            output.push_str("        return Some(result);\n");
        } else {
            output.push_str(&format!(
                "        return Some(GateResult::ask(format!(\"{}: {{}}\", reason)));\n",
                name
            ));
        }
        output.push_str("    }\n\n");
    }

    // Handle API rules
    if let Some(ref api) = program.api_rules {
        output.push_str(&generate_api_rules(name, api));
        output.push('\n');
    }

    // Handle bare ask rule (matches any invocation of the program)
    if let Some(ask) = bare_ask {
        output.push_str(&format!(
            "    // Bare ask rule - any {} invocation asks\n",
            name
        ));
        output.push_str(&format!(
            "    Some(GateResult::ask(\"{}: {}\"){})\n",
            name,
            escape_rust_string(&ask.reason),
            auto_hold_suffix(ask)
        ));
    } else {
        // Handle unknown action (bare_block already returned early above)
        match program.unknown_action {
            UnknownAction::Ask => {
                output.push_str(&format!(
                    "    Some(GateResult::ask(format!(\"{}: {{}}\", subcmd_single)))\n",
                    name
                ));
            }
            UnknownAction::Allow => {
                output.push_str("    Some(GateResult::allow())\n");
            }
            UnknownAction::Skip => {
                output.push_str("    None\n");
            }
            UnknownAction::Block => {
                output.push_str(&format!(
                    "    Some(GateResult::block(format!(\"{}: unknown subcommand {{}}\", subcmd_single)))\n",
                    name
                ));
            }
        }
    }

    output.push_str("}\n");

    output
}

fn generate_subcommand_match(parts: &[&str]) -> String {
    match parts.len() {
        0 => "true".to_string(),
        1 => format!("subcmd_single == \"{}\"", escape_rust_string(parts[0])),
        2 => format!(
            "cmd.args.len() >= 2 && cmd.args[0] == \"{}\" && cmd.args[1] == \"{}\"",
            escape_rust_string(parts[0]),
            escape_rust_string(parts[1])
        ),
        _ => {
            let checks: Vec<String> = parts
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    // Index 0 uses `.first()` so the generated code satisfies
                    // clippy's `get_first` lint (the crate builds under
                    // `-D warnings`); later indices use `.get(i)`.
                    let accessor = if i == 0 {
                        "cmd.args.first()".to_string()
                    } else {
                        format!("cmd.args.get({i})")
                    };
                    format!(
                        "{accessor} == Some(&\"{}\".to_string())",
                        escape_rust_string(p)
                    )
                })
                .collect();
            format!(
                "cmd.args.len() >= {} && {}",
                parts.len(),
                checks.join(" && ")
            )
        }
    }
}

fn generate_api_rules(name: &str, api: &ApiRules) -> String {
    let mut output = String::new();

    output.push_str(&format!(
        "    // API rules for '{} {}'\n",
        name, api.trigger
    ));
    output.push_str(&format!(
        "    if subcmd_single == \"{}\" {{\n",
        escape_rust_string(&api.trigger)
    ));

    let method_flags: Vec<String> = api
        .method_flags
        .iter()
        .map(|f| format!("\"{}\"", escape_rust_string(f)))
        .collect();
    let safe_methods: Vec<String> = api
        .safe_methods
        .iter()
        .map(|m| format!("\"{}\"", m.to_uppercase()))
        .collect();

    // Check for explicit method flag first
    output.push_str("        let explicit_method = cmd.args.iter()\n");
    output.push_str("            .position(|a| [");
    output.push_str(&method_flags.join(", "));
    output.push_str("].contains(&a.as_str()))\n");
    output.push_str("            .and_then(|i| cmd.args.get(i + 1))\n");
    output.push_str("            .map(|s| s.to_uppercase());\n");

    // Check for read-only endpoints (e.g., search/ for GitHub API)
    let has_read_only = !api.read_only_endpoints.is_empty();
    if has_read_only {
        let read_only_prefixes: Vec<String> = api
            .read_only_endpoints
            .iter()
            .map(|p| format!("\"{}\"", escape_rust_string(p)))
            .collect();
        // Find the endpoint: first arg after trigger that doesn't start with -
        output.push_str("        let endpoint = cmd.args.iter()\n");
        output.push_str("            .skip(1)  // skip 'api'\n");
        output.push_str("            .find(|a| !a.starts_with('-'));\n");
        output.push_str(&format!(
            "        let is_read_only_endpoint = endpoint.is_some_and(|e| [{}].iter().any(|p| e.starts_with(p)));\n",
            read_only_prefixes.join(", ")
        ));
    }

    // Check for implicit POST flags (e.g., -f, --field for gh api)
    if !api.implicit_post_flags.is_empty() {
        let implicit_flags: Vec<String> = api
            .implicit_post_flags
            .iter()
            .map(|f| format!("\"{}\"", escape_rust_string(f)))
            .collect();
        output.push_str("        let has_implicit_post = cmd.args.iter().any(|a| {\n");
        output.push_str("            let arg = a.as_str();\n");
        output.push_str(&format!(
            "            [{}].iter().any(|f| arg == *f || arg.starts_with(&format!(\"{{}}=\", f)))\n",
            implicit_flags.join(", ")
        ));
        output.push_str("        });\n");
        output.push_str("        let method = explicit_method.unwrap_or_else(|| {\n");
        if has_read_only {
            // Read-only endpoints ignore implicit POST flags
            output.push_str("            if is_read_only_endpoint {\n");
            output.push_str("                \"GET\".to_string()\n");
            output.push_str("            } else if has_implicit_post {\n");
        } else {
            output.push_str("            if has_implicit_post {\n");
        }
        output.push_str("                \"POST\".to_string()\n");
        output.push_str("            } else {\n");
        if let Some(ref default) = api.default_method {
            output.push_str(&format!(
                "                \"{}\".to_string()\n",
                default.to_uppercase()
            ));
        } else {
            output.push_str("                String::new()\n");
        }
        output.push_str("            }\n");
        output.push_str("        });\n");
    } else if let Some(ref default) = api.default_method {
        output.push_str(&format!(
            "        let method = explicit_method.unwrap_or_else(|| \"{}\".to_string());\n",
            default.to_uppercase()
        ));
    } else {
        output.push_str("        let method = explicit_method.unwrap_or_default();\n");
    }

    output.push_str(&format!(
        "        if [{}].contains(&method.as_str()) {{\n",
        safe_methods.join(", ")
    ));
    output.push_str("            return Some(GateResult::allow());\n");
    output.push_str("        }\n");
    output.push_str(&format!(
        "        return Some(GateResult::ask(format!(\"{} {}: {{}} request\", method)));\n",
        name, api.trigger
    ));
    output.push_str("    }\n");

    output
}

fn generate_master_check(rule_files: &[(String, RuleFile)]) -> String {
    let mut output = String::new();

    output.push_str("/// Check command against all declarative rules\n");
    output
        .push_str("/// Returns Some(GateResult) if handled by declarative rules, None otherwise\n");
    output.push_str("pub fn check_declarative(cmd: &CommandInfo) -> Option<GateResult> {\n");

    // First check safe commands
    output.push_str("    // Check safe commands first\n");
    output.push_str("    if let Some(result) = check_safe_command(cmd) {\n");
    output.push_str("        return Some(result);\n");
    output.push_str("    }\n\n");

    // Check conditional allows
    output.push_str("    // Check conditional allow rules\n");
    output.push_str("    if let Some(result) = check_conditional_allow(cmd) {\n");
    output.push_str("        return Some(result);\n");
    output.push_str("    }\n\n");

    // Check each program
    output.push_str("    // Check program-specific rules\n");
    for (_, rules) in rule_files {
        for program in &rules.programs {
            let fn_name = program.name.replace('-', "_");
            output.push_str(&format!(
                "    if let Some(result) = check_{}_declarative(cmd) {{\n",
                fn_name
            ));
            output.push_str("        return Some(result);\n");
            output.push_str("    }\n");
        }
    }

    output.push_str("\n    None\n");
    output.push_str("}\n");

    output
}

fn generate_gate_functions(rule_files: &[(String, RuleFile)]) -> String {
    let mut output = String::new();

    output.push_str("// === Generated Gate Functions ===\n");
    output.push_str("// These replace manual routing in gate files.\n");
    output.push_str("// Add tool to TOML, rebuild, done - no Rust changes needed.\n\n");

    for (name, rules) in rule_files {
        // Skip files with no programs (like basics which only has safe_commands)
        if rules.programs.is_empty() {
            continue;
        }

        let gate_name = name.replace('-', "_");

        // Collect all program names and aliases this gate handles
        let mut all_names: Vec<&str> = Vec::new();
        for program in &rules.programs {
            all_names.push(&program.name);
            for alias in &program.aliases {
                all_names.push(alias);
            }
        }

        // Build a set of programs with custom handlers
        let custom_programs: HashSet<&str> = rules
            .custom_handlers
            .iter()
            .map(|h| h.program.as_str())
            .collect();

        output.push_str(&format!(
            "/// Generated gate for {} - handles: {}\n",
            name,
            all_names.join(", ")
        ));
        output.push_str(&format!("/// Custom handlers needed for: {:?}\n", {
            let mut sorted: Vec<_> = custom_programs.iter().collect();
            sorted.sort();
            sorted
        }));
        output.push_str(&format!(
            "pub fn check_{}_gate(cmd: &CommandInfo) -> GateResult {{\n",
            gate_name
        ));

        // Match on program name
        output.push_str("    match cmd.program.as_str() {\n");

        for program in &rules.programs {
            let fn_name = program.name.replace('-', "_");

            // Collect names to match (program name + aliases)
            let mut names = vec![format!("\"{}\"", program.name)];
            for alias in &program.aliases {
                names.push(format!("\"{}\"", alias));
            }

            if custom_programs.contains(program.name.as_str()) {
                // Program has custom handler - skip, caller must handle
                output.push_str(&format!(
                    "        {} => GateResult::skip(), // custom handler: {}\n",
                    names.join(" | "),
                    rules
                        .custom_handlers
                        .iter()
                        .find(|h| h.program == program.name)
                        .map(|h| h.handler.as_str())
                        .unwrap_or("unknown")
                ));
            } else {
                // Pure declarative - call generated function
                output.push_str(&format!(
                    "        {} => check_{}_declarative(cmd).unwrap_or_else(GateResult::skip),\n",
                    names.join(" | "),
                    fn_name
                ));
            }
        }

        output.push_str("        _ => GateResult::skip(),\n");
        output.push_str("    }\n");
        output.push_str("}\n\n");

        // Generate list of programs handled by this gate
        output.push_str(&format!("/// Programs handled by the {} gate\n", name));
        output.push_str(&format!(
            "pub static {}_PROGRAMS: &[&str] = &[\n",
            gate_name.to_uppercase()
        ));
        for program in &rules.programs {
            output.push_str(&format!("    \"{}\",\n", program.name));
            for alias in &program.aliases {
                output.push_str(&format!("    \"{}\",\n", alias));
            }
        }
        output.push_str("];\n\n");
    }

    output
}

// ============================================================================
// File Editing Detection Code Generation
// ============================================================================

/// Represents a file-editing rule extracted from TOML
#[derive(Debug)]
struct FileEditingRule {
    program: String,
    aliases: Vec<String>,
    subcommand: Option<String>,
    if_flags_any: Vec<String>,
    // True if this is a bare ask with accept_edits_auto_allow (no subcommand or flags needed)
    is_bare: bool,
}

fn generate_file_editing_code(rule_files: &[(String, RuleFile)]) -> String {
    let mut output = String::new();

    output.push_str(
        "// ============================================================================\n",
    );
    output.push_str("// File Editing Detection (generated from accept_edits_auto_allow rules)\n");
    output.push_str(
        "// ============================================================================\n\n",
    );

    // Collect all file-editing rules from TOML
    let mut rules: Vec<FileEditingRule> = Vec::new();
    let mut programs_set: HashSet<String> = HashSet::new();

    for (_, rule_file) in rule_files {
        // Collect from ask rules
        for program in &rule_file.programs {
            for ask in &program.ask {
                if ask.accept_edits_auto_allow {
                    let rule = FileEditingRule {
                        program: program.name.clone(),
                        aliases: program.aliases.clone(),
                        subcommand: ask.subcommand.clone(),
                        if_flags_any: ask.if_flags_any.clone(),
                        is_bare: ask.subcommand.is_none()
                            && ask.subcommand_prefix.is_none()
                            && ask.if_flags_any.is_empty(),
                    };
                    programs_set.insert(program.name.clone());
                    for alias in &program.aliases {
                        programs_set.insert(alias.clone());
                    }
                    rules.push(rule);
                }
            }
        }

        // Collect from conditional_allow rules (these have unless_flags that trigger ask)
        for cond in &rule_file.conditional_allow {
            if cond.accept_edits_auto_allow && cond.on_flag_present == OnFlagAction::Ask {
                let rule = FileEditingRule {
                    program: cond.program.clone(),
                    aliases: cond.aliases.clone(),
                    subcommand: None,
                    if_flags_any: cond.unless_flags.clone(),
                    is_bare: false,
                };
                programs_set.insert(cond.program.clone());
                for alias in &cond.aliases {
                    programs_set.insert(alias.clone());
                }
                rules.push(rule);
            }
        }
    }

    // Generate static list of file-editing programs
    let mut programs: Vec<&str> = programs_set.iter().map(String::as_str).collect();
    programs.sort();

    output.push_str(
        "/// Programs that have file-editing rules (generated from accept_edits_auto_allow)\n",
    );
    output.push_str(
        "pub static FILE_EDITING_PROGRAMS: LazyLock<HashSet<&str>> = LazyLock::new(|| {\n",
    );
    output.push_str("    [\n");
    for prog in &programs {
        output.push_str(&format!("        \"{}\",\n", escape_rust_string(prog)));
    }
    output.push_str("    ].into_iter().collect()\n");
    output.push_str("});\n\n");

    // Generate the check function
    output.push_str("/// Check if a command is a file-editing command (generated from accept_edits_auto_allow rules)\n");
    output
        .push_str("/// Returns true if the command should be auto-allowed in acceptEdits mode.\n");
    output.push_str("pub fn is_file_editing_command(cmd: &CommandInfo) -> bool {\n");
    output.push_str(
        "    let base_program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);\n",
    );
    output.push_str("    \n");
    output.push_str(
        "    // Reject scoped npm packages: @scope/tool should not match bare \"tool\".\n",
    );
    output.push_str(
        "    // rsplit('/') strips the scope, which would let @evil/prettier match \"prettier\".\n",
    );
    output.push_str("    if cmd.program.starts_with('@') && base_program != cmd.program {\n");
    output.push_str("        return false;\n");
    output.push_str("    }\n\n");
    output.push_str("    // Quick check: is this a known file-editing program?\n");
    output.push_str("    if !FILE_EDITING_PROGRAMS.contains(base_program) {\n");
    output.push_str("        return false;\n");
    output.push_str("    }\n\n");

    // Group rules by program for efficient matching
    let mut rules_by_program: std::collections::HashMap<String, Vec<&FileEditingRule>> =
        std::collections::HashMap::new();
    for rule in &rules {
        rules_by_program
            .entry(rule.program.clone())
            .or_default()
            .push(rule);
        for alias in &rule.aliases {
            rules_by_program
                .entry(alias.clone())
                .or_default()
                .push(rule);
        }
    }

    // Generate match statement
    output.push_str("    match base_program {\n");

    // Sort programs for deterministic output
    let mut sorted_programs: Vec<&String> = rules_by_program.keys().collect();
    sorted_programs.sort();

    for prog in sorted_programs {
        let prog_rules = &rules_by_program[prog];
        output.push_str(&format!("        \"{}\" => {{\n", escape_rust_string(prog)));

        // Group by condition type for cleaner code
        let bare_rules: Vec<_> = prog_rules.iter().filter(|r| r.is_bare).collect();
        let flag_rules: Vec<_> = prog_rules
            .iter()
            .filter(|r| !r.if_flags_any.is_empty())
            .collect();
        let subcommand_rules: Vec<_> = prog_rules
            .iter()
            .filter(|r| r.subcommand.is_some() && r.if_flags_any.is_empty())
            .collect();

        // Bare rules (always file-editing for this program)
        if !bare_rules.is_empty() {
            output.push_str("            // Bare rule: always file-editing\n");
            output.push_str("            true\n");
        } else {
            let mut conditions: Vec<String> = Vec::new();

            // Flag-based rules
            for rule in &flag_rules {
                let flags: Vec<String> = rule
                    .if_flags_any
                    .iter()
                    .map(|f| format!("\"{}\"", escape_rust_string(f)))
                    .collect();
                if let Some(ref subcmd) = rule.subcommand {
                    conditions.push(format!(
                        "(cmd.args.first().is_some_and(|a| a == \"{}\") && cmd.args.iter().any(|a| [{}].contains(&a.as_str())))",
                        escape_rust_string(subcmd),
                        flags.join(", ")
                    ));
                } else {
                    conditions.push(format!(
                        "cmd.args.iter().any(|a| [{}].contains(&a.as_str()))",
                        flags.join(", ")
                    ));
                }
            }

            // Subcommand-only rules (no flags required)
            for rule in &subcommand_rules {
                if let Some(ref subcmd) = rule.subcommand {
                    conditions.push(format!(
                        "cmd.args.first().is_some_and(|a| a == \"{}\")",
                        escape_rust_string(subcmd)
                    ));
                }
            }

            if conditions.is_empty() {
                output.push_str("            false\n");
            } else if conditions.len() == 1 {
                // Strip outer parens when single condition (avoids clippy warning)
                let cond = &conditions[0];
                let trimmed = cond
                    .strip_prefix('(')
                    .and_then(|s| s.strip_suffix(')'))
                    .unwrap_or(cond);
                output.push_str(&format!("            {}\n", trimmed));
            } else {
                output.push_str("            ");
                output.push_str(&conditions.join("\n                || "));
                output.push('\n');
            }
        }

        output.push_str("        }\n");
    }

    output.push_str("        _ => false,\n");
    output.push_str("    }\n");
    output.push_str("}\n\n");

    output
}

// ============================================================================
// Security Floor Code Generation
// ============================================================================

/// The regex-static name for a floor row id (`pipe-bash` -> `FLOOR_PIPE_BASH_RE`).
fn floor_static_name(id: &str) -> String {
    format!("FLOOR_{}_RE", id.to_uppercase().replace('-', "_"))
}

/// Split a `within`-row reason around its `{match}` placeholder into
/// (prefix, suffix). Validation guarantees the placeholder is present.
fn split_match_placeholder(reason: &str) -> (String, String) {
    match reason.split_once("{match}") {
        Some((a, b)) => (a.to_string(), b.to_string()),
        None => (reason.to_string(), String::new()),
    }
}

/// Emit the `check_security_floor` matcher plus its regex statics from
/// `rules/security.toml`. Rows run in file order (first-match-wins); each is a
/// regex `is_match`, a `within` capture-iterate, or a Rust `handler` call.
fn generate_security_floor(floor: &SecurityFloorFile) -> String {
    let mut out = String::new();

    out.push_str(
        "\n// ============================================================================\n",
    );
    out.push_str("// Security Floor (generated from rules/security.toml)\n");
    out.push_str(
        "// ============================================================================\n\n",
    );
    out.push_str("use crate::rules_schema::FloorTier;\n");
    out.push_str("use crate::security_floor::FloorHit;\n");
    out.push_str("use regex::Regex;\n\n");

    // Compiled regex statics, one per regex row.
    for p in &floor.patterns {
        if let Some(re) = &p.regex {
            out.push_str(&format!(
                "static {name}: LazyLock<Regex> = LazyLock::new(|| {{\n    Regex::new(r#\"{re}\"#).expect(\"security floor '{id}' regex must compile\")\n}});\n",
                name = floor_static_name(&p.id),
                re = re,
                id = escape_rust_string(&p.id),
            ));
        }
    }
    out.push('\n');

    out.push_str("/// Raw-string security floor: first-match-wins over rules/security.toml.\n");
    out.push_str("/// `comment_stripped` has comments removed (quotes intact); `unquoted` also\n");
    out.push_str(
        "/// has quoted strings blanked. Returns the first matching row's tier + reason.\n",
    );
    out.push_str(
        "pub fn check_security_floor(comment_stripped: &str, unquoted: &str) -> Option<FloorHit> {\n",
    );

    for p in &floor.patterns {
        out.push_str(&generate_floor_row(p));
    }

    out.push_str("    None\n");
    out.push_str("}\n");
    out
}

/// Emit one floor row's check into `check_security_floor`.
fn generate_floor_row(p: &SecurityPattern) -> String {
    let mut out = String::new();

    let tier = match p.tier {
        FloorTier::HardAsk => "FloorTier::HardAsk",
        FloorTier::SoftAsk => "FloorTier::SoftAsk",
    };

    // Handler row: the named Rust function owns matching and its own reason.
    if let Some(handler) = &p.handler {
        out.push_str(&format!(
            "    if let Some(hit) = crate::security_floor::{handler}(comment_stripped, unquoted) {{\n        return Some(hit);\n    }}\n",
        ));
        return out;
    }

    let scan = match p.scan {
        FloorScan::QuoteStripped => "unquoted",
        FloorScan::CommentStripped => "comment_stripped",
    };
    let name = floor_static_name(&p.id);
    // `auto` only means something for soft asks; hard asks promote to deny
    // under auto mode before this flag is ever consulted.
    let hold = p.tier == FloorTier::SoftAsk && p.auto == AutoDisposition::Prompt;
    let substring_guard = if p.requires_substring.is_empty() {
        None
    } else {
        let checks = p
            .requires_substring
            .iter()
            .map(|s| format!("{scan}.contains(\"{}\")", escape_rust_string(s)))
            .collect::<Vec<_>>();
        let expression = checks.join(" || ");
        Some(if checks.len() == 1 {
            expression
        } else {
            format!("({expression})")
        })
    };

    // within = command_substitution: iterate each match, check the dangerous
    // inner substrings, and echo the (30-character-truncated) match into the reason.
    if p.within == Some(FloorWithin::CommandSubstitution) {
        let inner: Vec<String> = p
            .inner_contains_any
            .iter()
            .map(|s| format!("\"{}\"", escape_rust_string(s)))
            .collect();
        let (prefix, suffix) = split_match_placeholder(&p.reason);
        if let Some(guard) = &substring_guard {
            out.push_str(&format!("    if {guard} {{\n"));
        }
        out.push_str(&format!("    for cap in {name}.captures_iter({scan}) {{\n"));
        out.push_str("        let m = cap.get(0).map_or(\"\", |x| x.as_str());\n");
        out.push_str(&format!(
            "        if [{}].into_iter().any(|d| m.contains(d)) {{\n",
            inner.join(", ")
        ));
        out.push_str(
            "            let truncated = m.char_indices().nth(30).map_or(m, |(idx, _)| &m[..idx]);\n",
        );
        out.push_str(&format!(
            "            let mut reason = String::from(\"{}\");\n",
            escape_rust_string(&prefix)
        ));
        out.push_str("            reason.push_str(truncated);\n");
        out.push_str(&format!(
            "            reason.push_str(\"{}\");\n",
            escape_rust_string(&suffix)
        ));
        out.push_str(&format!(
            "            return Some(FloorHit {{ tier: {tier}, reason, hold_in_auto: {hold} }});\n"
        ));
        out.push_str("        }\n");
        out.push_str("    }\n");
        if substring_guard.is_some() {
            out.push_str("    }\n");
        }
        return out;
    }

    // Plain regex row, with an optional cheap substring pre-guard.
    let guard = substring_guard.map_or_else(String::new, |guard| format!("{guard} && "));
    out.push_str(&format!(
        "    if {guard}{name}.is_match({scan}) {{\n        return Some(FloorHit {{ tier: {tier}, reason: \"{reason}\".to_string(), hold_in_auto: {hold} }});\n    }}\n",
        reason = escape_rust_string(&p.reason),
    ));
    out
}

fn escape_rust_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Generate a GateResult::allow() call, with optional reason
fn generate_allow_call(reason: &Option<String>) -> String {
    match reason {
        Some(r) => format!(
            "Some(GateResult::allow_with_reason(\"{}\"))",
            escape_rust_string(r)
        ),
        None => "Some(GateResult::allow())".to_string(),
    }
}

fn write_if_changed(path: &Path, content: &[u8]) -> io::Result<bool> {
    if fs::read(path).is_ok_and(|existing| existing == content) {
        return Ok(false);
    }
    fs::write(path, content)?;
    Ok(true)
}

fn rustfmt_available() -> bool {
    Command::new("rustfmt")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn format_with_rustfmt(code: &str) -> Option<String> {
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2024", "--emit", "stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(code.as_bytes()).ok()?;
    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        eprintln!(
            "Warning: rustfmt failed for generated rules: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn generation_fingerprint(code: &str, formatter_identity: &str) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in code
        .bytes()
        .chain(std::iter::once(0))
        .chain(formatter_identity.bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn existing_generation_fingerprint(path: &Path) -> Option<u64> {
    let content = fs::read_to_string(path).ok()?;
    let (marker, body) = content.split_once('\n')?;
    let (input, expected_content) = marker
        .strip_prefix(GENERATED_FINGERPRINT_PREFIX)?
        .split_once(':')?;
    let expected_content = u64::from_str_radix(expected_content, 16).ok()?;
    if generation_fingerprint(body, "formatted-output") != expected_content {
        return None;
    }
    u64::from_str_radix(input, 16).ok()
}

fn format_rust(code: &str) -> String {
    syn::parse_file(code)
        .map(|tree| prettyplease::unparse(&tree))
        .unwrap_or_else(|e| {
            eprintln!("Warning: failed to parse generated code for formatting: {e}");
            code.to_string()
        })
}

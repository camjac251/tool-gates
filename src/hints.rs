//! Modern CLI hints for legacy commands.
//!
//! Detects when legacy commands are used and suggests modern alternatives.
//! These hints are added to `additionalContext` so Claude can learn better patterns.
//!
//! Hints are only shown if the modern tool is actually installed (checked via cache).

use crate::models::CommandInfo;
use crate::tool_cache::{ToolCache, get_cache};
use std::sync::OnceLock;

/// Global tool cache - loaded once per process
static TOOL_CACHE: OnceLock<ToolCache> = OnceLock::new();

/// Get the tool cache (loads from disk on first call)
fn cache() -> &'static ToolCache {
    TOOL_CACHE.get_or_init(get_cache)
}

/// A hint suggesting a modern alternative to a legacy command.
#[derive(Debug, Clone)]
pub struct ModernHint {
    pub legacy_command: &'static str,
    pub modern_command: &'static str,
    pub hint: String,
}

/// Check if a command could benefit from a modern alternative and return a hint.
/// Only returns hints for tools that are actually installed.
/// Respects `features.hints` toggle and `hints.disable` list from config.
pub fn get_modern_hint(cmd: &CommandInfo) -> Option<ModernHint> {
    let config = crate::config::get();

    // Global hints toggle
    if !config.features.hints {
        return None;
    }

    // Per-command disable list
    if config.hints.disable.iter().any(|d| d == &cmd.program) {
        return None;
    }

    let hint = match cmd.program.as_str() {
        // File viewing (only when used with files, not pipes)
        "cat" => hint_cat(cmd),
        "head" => hint_head(cmd),
        "tail" => hint_tail(cmd),
        "less" | "more" => Some(hint_less(cmd)),
        // Search & find
        "grep" => hint_grep(cmd),
        "ag" | "ack" => Some(hint_ag_ack(cmd)),
        "find" => Some(hint_find(cmd)),
        // Text processing
        "sed" => hint_sed(cmd),
        "awk" => hint_awk(cmd),
        "wc" => hint_wc(cmd),
        // File listing & disk
        "ls" => hint_ls(cmd),
        "du" => hint_du(cmd),
        "tree" => hint_tree(cmd),
        // Process (for debugging)
        "ps" => hint_ps(cmd),
        // Network (for API exploration)
        "curl" => hint_curl(cmd),
        "wget" => hint_wget(cmd),
        // Diff & hex (code understanding)
        "diff" => hint_diff(cmd),
        "xxd" | "hexdump" => Some(hint_hex(cmd)),
        // Code stats
        "cloc" => Some(hint_cloc(cmd)),
        // Documentation (understanding APIs/libraries)
        "man" => hint_man(cmd),
        // Anti-patterns (bad flags, wrong tool for job)
        "bat" => hint_bat_flags(cmd),
        "rg" => hint_rg_body_capture(cmd),
        "git" => hint_git_antipatterns(cmd),
        _ => None,
    }?;

    // Only return hint if the modern tool is installed
    if cache().is_available(hint.modern_command) {
        Some(hint)
    } else {
        None
    }
}

fn hint_cat(cmd: &CommandInfo) -> Option<ModernHint> {
    let files: Vec<_> = cmd.args.iter().filter(|a| !a.starts_with('-')).collect();
    // No file argument means pipe usage (echo | cat) - no hint needed
    if files.is_empty() {
        return None;
    }

    let file = files[0];
    let ext_hint = if file.ends_with(".json") {
        " (JSON syntax highlighting)"
    } else if file.ends_with(".md") {
        " (Markdown rendering)"
    } else if file.ends_with(".rs") || file.ends_with(".py") || file.ends_with(".ts") {
        " (code syntax highlighting)"
    } else {
        ""
    };

    Some(ModernHint {
        legacy_command: "cat",
        modern_command: "bat",
        hint: format!(
            "Use `bat {}` instead of `cat`. Syntax highlighting and line numbers{}.",
            file, ext_hint
        ),
    })
}

fn hint_head(cmd: &CommandInfo) -> Option<ModernHint> {
    let mut lines = "10".to_string();
    let mut file = String::new();

    let mut iter = cmd.args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "-n" {
            if let Some(n) = iter.next() {
                lines = n.clone();
            }
        } else if arg.starts_with("-n") && arg.len() > 2 {
            lines = arg[2..].to_string();
        } else if !arg.starts_with('-') {
            file = arg.clone();
        }
    }

    // No file argument means pipe usage (command | head) - no hint needed
    if file.is_empty() {
        return None;
    }

    let bat_range = format!(":{}", lines);
    Some(ModernHint {
        legacy_command: "head",
        modern_command: "bat",
        hint: format!(
            "Use `bat -r {} {}` instead of `head` for file viewing.",
            bat_range, file,
        ),
    })
}

fn hint_tail(cmd: &CommandInfo) -> Option<ModernHint> {
    // Parse -n flag to get line count
    let mut lines = "10".to_string();
    let mut file = String::new();
    let mut follow = false;

    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-n" {
            if let Some(n) = iter.next() {
                lines = n.clone();
            }
        } else if arg.starts_with("-n") && arg.len() > 2 {
            lines = arg[2..].to_string();
        } else if arg == "-f" || arg == "--follow" {
            follow = true;
        } else if !arg.starts_with('-') {
            file = arg.clone();
        }
    }

    // tail -f is fine - no hint needed (bat doesn't support following)
    if follow {
        return None;
    }

    // No file argument means pipe usage (command | tail) - no hint needed
    if file.is_empty() {
        return None;
    }

    let bat_range = format!("-{}:", lines);
    Some(ModernHint {
        legacy_command: "tail",
        modern_command: "bat",
        hint: format!(
            "Use `bat -r {} {}` instead of `tail` for file viewing.",
            bat_range, file,
        ),
    })
}

fn hint_grep(cmd: &CommandInfo) -> Option<ModernHint> {
    if cmd.args.is_empty() {
        return None;
    }

    // Extract non-flag args (pattern + targets) for context-aware hints.
    let mut non_flag_args: Vec<&str> = Vec::new();
    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            // Flags with a following value
            "-e" | "--regexp" | "-f" | "--file" => {
                if let Some(value) = iter.next() {
                    non_flag_args.push(value.as_str());
                }
            }
            _ if !arg.starts_with('-') => non_flag_args.push(arg.as_str()),
            _ => {}
        }
    }

    let pattern = non_flag_args.first().copied().unwrap_or("");
    let targets = if non_flag_args.len() > 1 {
        &non_flag_args[1..]
    } else {
        &[]
    };

    let code_search =
        looks_like_code_pattern(pattern) || targets.iter().any(|t| is_code_search_target(t));
    if code_search {
        return Some(ModernHint {
            legacy_command: "grep",
            modern_command: "sg",
            hint: "Use `sg -p <pattern> <path>` instead of `grep` for code searches. AST-aware structural matching. Use `rg` for plain text.".to_string(),
        });
    }

    // Check for flags that rg handles better
    let has_recursive = cmd
        .args
        .iter()
        .any(|a| a == "-r" || a == "-R" || a == "--recursive");
    let has_context = cmd
        .args
        .iter()
        .any(|a| a.starts_with("-A") || a.starts_with("-B") || a.starts_with("-C"));

    let hint = if has_recursive {
        "Use `rg <pattern>` instead of `grep -r`. Recursive by default, respects .gitignore, faster."
    } else if has_context {
        "Use `rg <pattern>` instead of `grep`. Same -A/-B/-C flags, faster, better defaults."
    } else {
        "Use `rg <pattern>` instead of `grep`. Faster, recursive by default, respects .gitignore."
    };

    Some(ModernHint {
        legacy_command: "grep",
        modern_command: "rg",
        hint: hint.to_string(),
    })
}

fn hint_find(cmd: &CommandInfo) -> ModernHint {
    // Check for common patterns and provide direct replacements.
    let mut name_pattern: Option<&str> = None;
    let mut type_filter: Option<&str> = None;

    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-name" | "-iname" => {
                if let Some(pattern) = iter.next() {
                    name_pattern = Some(pattern);
                }
            }
            "-type" => {
                if let Some(kind) = iter.next() {
                    type_filter = Some(kind);
                }
            }
            _ => {}
        }
    }

    let hint = if let Some(pattern) = name_pattern {
        if let Some(kind) = type_filter {
            format!(
                "Use `fd -t {} {} .` instead of `find`. Faster, simpler syntax, .gitignore-aware.",
                kind, pattern
            )
        } else {
            format!(
                "Use `fd {} .` instead of `find`. Faster, simpler syntax, .gitignore-aware.",
                pattern
            )
        }
    } else if let Some(kind) = type_filter {
        format!(
            "Use `fd -t {} .` instead of `find`. Faster, simpler syntax, .gitignore-aware.",
            kind
        )
    } else {
        "Use `fd <pattern> <path>` instead of `find`. Faster, simpler syntax, .gitignore-aware."
            .to_string()
    };

    ModernHint {
        legacy_command: "find",
        modern_command: "fd",
        hint,
    }
}

fn is_code_search_target(target: &str) -> bool {
    let lower = target
        .trim_matches(|c| c == '"' || c == '\'')
        .to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }

    const CODE_DIR_MARKERS: &[&str] = &[
        "src", "lib", "app", "pkg", "cmd", "internal", "tests", "test", "spec", "crates",
        "include", "examples",
    ];
    if CODE_DIR_MARKERS.iter().any(|marker| {
        lower == *marker
            || lower.starts_with(&format!("{marker}/"))
            || lower.starts_with(&format!("./{marker}/"))
            || lower.contains(&format!("/{marker}/"))
    }) {
        return true;
    }

    const CODE_EXTENSIONS: &[&str] = &[
        ".rs", ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt", ".kts", ".c", ".h",
        ".cpp", ".hpp", ".cs", ".rb", ".php", ".swift", ".scala", ".sh", ".bash", ".zsh", ".sql",
        ".yaml", ".yml", ".toml", ".json", ".md",
    ];
    CODE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

fn looks_like_code_pattern(pattern: &str) -> bool {
    let lower = pattern.to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }

    [
        "function ",
        "class ",
        "import ",
        "export ",
        "def ",
        "struct ",
        "enum ",
        "impl ",
        "fn ",
        "const ",
        "let ",
        "var ",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || lower.contains("::")
        || lower.contains("=>")
        || lower.contains("->")
}

fn hint_sed(cmd: &CommandInfo) -> Option<ModernHint> {
    // Only hint for substitution patterns
    let has_subst = cmd
        .args
        .iter()
        .any(|a| a.contains("s/") || a.contains("s#"));
    let has_inplace = cmd.args.iter().any(|a| a == "-i" || a.starts_with("-i"));

    if !has_subst {
        return None;
    }

    let hint = if has_inplace {
        "Use `sd <find> <replace> <file>` instead of `sed -i`. Simpler syntax, no escaping needed."
    } else {
        "Use `sd <find> <replace>` instead of `sed`. No 's/.../.../g' syntax needed."
    };

    Some(ModernHint {
        legacy_command: "sed",
        modern_command: "sd",
        hint: hint.to_string(),
    })
}

fn hint_ls(cmd: &CommandInfo) -> Option<ModernHint> {
    // Only hint for detailed listings
    // Match short flags like -l, -la, -al, but not long flags like --help or --color
    let has_long = cmd
        .args
        .iter()
        .any(|a| (a.starts_with('-') && !a.starts_with("--") && a.contains('l')) || a == "--long");
    let has_all = cmd.args.iter().any(|a| {
        (a.starts_with('-') && !a.starts_with("--") && a.contains('a'))
            || a == "--all"
            || a == "--almost-all"
    });

    if !has_long && !has_all {
        return None; // Simple ls is fine
    }

    Some(ModernHint {
        legacy_command: "ls",
        modern_command: "eza",
        hint: "Use `eza -la` instead of `ls -la`. Git status integration and better formatting."
            .to_string(),
    })
}

fn hint_du(cmd: &CommandInfo) -> Option<ModernHint> {
    // du -sh (summary) is a quick one-liner that's fine. Hint for deep/recursive usage.
    let is_summary = cmd.args.iter().any(|a| {
        (a.starts_with('-') && !a.starts_with("--") && a.contains('s')) || a == "--summarize"
    });
    if is_summary {
        return None;
    }

    Some(ModernHint {
        legacy_command: "du",
        modern_command: "dust",
        hint:
            "Use `dust` instead of `du` for disk usage trees. Visual output with better formatting."
                .to_string(),
    })
}

fn hint_ps(cmd: &CommandInfo) -> Option<ModernHint> {
    // Only hint for detailed process listings
    // BSD style: aux, -aux, axu (any combo of a, u, x)
    // POSIX style: -e, -A, -ef
    let has_all = cmd.args.iter().any(|a| {
        a == "-e"
            || a == "-A"
            || a == "-ef"
            || a == "aux"
            || a == "-aux"
            || a == "axu"
            || a == "-axu"
    });

    if !has_all {
        return None;
    }

    Some(ModernHint {
        legacy_command: "ps",
        modern_command: "procs",
        hint: "Use `procs` instead of `ps`. Better formatting with tree view.".to_string(),
    })
}

fn hint_curl(cmd: &CommandInfo) -> Option<ModernHint> {
    // Check for JSON APIs or verbose flags
    let has_json = cmd
        .args
        .iter()
        .any(|a| a.contains("json") || a.contains("application/json"));
    let has_verbose = cmd.args.iter().any(|a| a == "-v" || a == "--verbose");

    if has_json || has_verbose {
        return Some(ModernHint {
            legacy_command: "curl",
            modern_command: "xh",
            hint: "Use `xh <url>` instead of `curl`. Automatic JSON formatting, cleaner output."
                .to_string(),
        });
    }

    None
}

fn hint_wget(cmd: &CommandInfo) -> Option<ModernHint> {
    // wget for file downloads (-O, -P, -r, -c) is the right tool. Only hint for simple fetches.
    let is_download = cmd.args.iter().any(|a| {
        a == "-O"
            || a.starts_with("-O")
            || a == "-P"
            || a.starts_with("-P")
            || a == "-r"
            || a == "--recursive"
            || a == "-c"
            || a == "--continue"
    });
    if is_download {
        return None;
    }

    Some(ModernHint {
        legacy_command: "wget",
        modern_command: "xh",
        hint:
            "Use `xh <url>` instead of `wget` for HTTP requests. For file downloads, wget is fine."
                .to_string(),
    })
}

fn hint_awk(cmd: &CommandInfo) -> Option<ModernHint> {
    // Check for simple field extraction patterns
    let has_print = cmd.args.iter().any(|a| a.contains("print $"));

    if has_print {
        return Some(ModernHint {
            legacy_command: "awk",
            modern_command: "choose",
            hint: "Use `choose <field>` instead of `awk`. Example: `choose 0 2` replaces awk '{print $1, $3}'.".to_string(),
        });
    }

    None
}

fn hint_wc(cmd: &CommandInfo) -> Option<ModernHint> {
    // Only hint for line counting with a file argument.
    // `command | wc -l` (pipe usage) is fine and has no good rg equivalent.
    let has_lines = cmd.args.iter().any(|a| a == "-l");
    let has_file = cmd.args.iter().any(|a| !a.starts_with('-'));

    if has_lines && has_file {
        return Some(ModernHint {
            legacy_command: "wc -l",
            modern_command: "rg",
            hint:
                "Use `rg -c '.' <file>` to count lines in a file. For counting piped output, `| wc -l` is fine."
                    .to_string(),
        });
    }

    None
}

fn hint_cloc(_cmd: &CommandInfo) -> ModernHint {
    ModernHint {
        legacy_command: "cloc",
        modern_command: "tokei",
        hint: "Use `tokei` instead of `cloc`. Faster with better formatting.".to_string(),
    }
}

fn hint_tree(_cmd: &CommandInfo) -> Option<ModernHint> {
    Some(ModernHint {
        legacy_command: "tree",
        modern_command: "eza",
        hint: "Use `eza -T` instead of `tree`. Git status integration and better formatting."
            .to_string(),
    })
}

fn hint_hex(cmd: &CommandInfo) -> ModernHint {
    let legacy = if cmd.program == "xxd" {
        "xxd"
    } else {
        "hexdump"
    };
    ModernHint {
        legacy_command: legacy,
        modern_command: "hexyl",
        hint: "Use `hexyl <file>` instead of the legacy hex viewer. Colored output, better formatting.".to_string(),
    }
}

fn hint_diff(cmd: &CommandInfo) -> Option<ModernHint> {
    let has_files = cmd.args.iter().filter(|a| !a.starts_with('-')).count() >= 2;

    if has_files {
        return Some(ModernHint {
            legacy_command: "diff",
            modern_command: "difft",
            hint: "Use `difft` for syntax-aware code diffs, or `git diff` for unified patches."
                .to_string(),
        });
    }

    None
}

// === Additional hints for code reading/understanding ===

fn hint_less(_cmd: &CommandInfo) -> ModernHint {
    ModernHint {
        legacy_command: "less",
        modern_command: "bat",
        hint: "Use `bat <file>` instead of `less`. Syntax highlighting and line numbers included."
            .to_string(),
    }
}

fn hint_man(cmd: &CommandInfo) -> Option<ModernHint> {
    // Only hint if looking up a command
    if cmd.args.is_empty() {
        return None;
    }

    let command = &cmd.args[0];
    Some(ModernHint {
        legacy_command: "man",
        modern_command: "tldr",
        hint: format!(
            "Use `tldr {}` instead of `man`. Practical examples, concise output.",
            command
        ),
    })
}

fn hint_ag_ack(cmd: &CommandInfo) -> ModernHint {
    ModernHint {
        legacy_command: if cmd.program == "ag" { "ag" } else { "ack" },
        modern_command: "rg",
        hint: format!(
            "Use `rg` instead of `{}`. Faster with similar interface.",
            cmd.program
        ),
    }
}

// === Git alias detection ===

/// Check if a git alias exists. Cached per-process via OnceLock.
fn has_git_alias(alias: &str) -> bool {
    use std::sync::Mutex;
    static GIT_ALIASES: OnceLock<Mutex<std::collections::HashMap<String, bool>>> = OnceLock::new();

    let cache = GIT_ALIASES.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());

    if let Some(&cached) = map.get(alias) {
        return cached;
    }

    let key = format!("alias.{alias}");
    let exists = std::process::Command::new("git")
        .args(["config", "--get", &key])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    map.insert(alias.to_string(), exists);
    exists
}

/// Return the short alias if it exists, otherwise the full command.
fn git_alias_or_raw(alias: &str, raw: &str) -> String {
    if has_git_alias(alias) {
        format!("git {alias}")
    } else {
        raw.to_string()
    }
}

// === Anti-pattern detection ===

fn hint_bat_flags(cmd: &CommandInfo) -> Option<ModernHint> {
    // Detect useless bat flags that are no-ops or counterproductive in piped output
    let bad_flags = [
        "--style",
        "-p",
        "--plain",
        "--paging",
        "--decorations",
        "--color",
    ];
    let used_bad: Vec<&str> = cmd
        .args
        .iter()
        .filter(|a| {
            bad_flags
                .iter()
                .any(|f| a.as_str() == *f || a.starts_with(&format!("{f}=")))
        })
        .map(|a| a.as_str())
        .collect();

    if used_bad.is_empty() {
        return None;
    }

    Some(ModernHint {
        legacy_command: "bat",
        modern_command: "bat",
        hint: format!(
            "bat flags {} are no-ops or counterproductive. Only use `-r START:END` (line range) and `-A` (show whitespace).",
            used_bad.join(", ")
        ),
    })
}

fn hint_rg_body_capture(cmd: &CommandInfo) -> Option<ModernHint> {
    // Detect rg -A (after context) targeting code directories, which suggests
    // trying to capture function/class bodies. sg is better for this.
    let has_after_context = cmd.args.iter().any(|a| {
        a == "-A"
            || (a.starts_with("-A") && a.len() > 2 && a[2..].chars().all(|c| c.is_ascii_digit()))
    });

    if !has_after_context {
        return None;
    }

    // Check if targeting code directories
    let targets_code = cmd.args.iter().any(|a| is_code_search_target(a));
    if !targets_code {
        return None;
    }

    Some(ModernHint {
        legacy_command: "rg",
        modern_command: "sg",
        hint: "Use `sg -p 'pattern' src/` instead of `rg -A` for capturing function/class bodies. AST-aware matching gives exact boundaries.".to_string(),
    })
}

fn hint_git_antipatterns(cmd: &CommandInfo) -> Option<ModernHint> {
    if cmd.args.is_empty() {
        return None;
    }

    let subcommand = cmd.args[0].as_str();

    match subcommand {
        "status" => {
            if cmd
                .args
                .iter()
                .any(|a| a == "-uall" || a == "--untracked-files=all")
            {
                return Some(ModernHint {
                    legacy_command: "git",
                    modern_command: "git",
                    hint: "Avoid `git status -uall` on large repos (memory issues). Use `git status` without -uall.".to_string(),
                });
            }
            None
        }
        "add" => {
            // Interactive staging hangs agents
            if cmd
                .args
                .iter()
                .any(|a| a == "-p" || a == "--patch" || a == "-i" || a == "--interactive")
            {
                let diff_cmd =
                    git_alias_or_raw("adiff", "git -c core.pager= diff --no-color --no-ext-diff");
                return Some(ModernHint {
                    legacy_command: "git",
                    modern_command: "git",
                    hint: format!(
                        "Never use `git add -p` or `git add -i` (interactive, hangs agent). Use `{diff_cmd} | grepdiff 'pattern' --output-matching=hunk | git apply --cached` for surgical staging, or `git absorb --and-rebase` to auto-fold changes."
                    ),
                });
            }
            let is_bulk = cmd
                .args
                .iter()
                .any(|a| a == "-A" || a == "--all" || a == ".");
            if is_bulk {
                return Some(ModernHint {
                    legacy_command: "git",
                    modern_command: "git",
                    hint: "Stage specific files by name instead of `git add -A` or `git add .` (can include secrets, large binaries).".to_string(),
                });
            }
            None
        }
        "rebase" => {
            // Interactive rebase hangs agents
            if cmd.args.iter().any(|a| a == "-i" || a == "--interactive") {
                return Some(ModernHint {
                    legacy_command: "git",
                    modern_command: "git",
                    hint: "Never use `git rebase -i` (interactive, hangs agent). Use `git revise --autosquash` for fixups, `git absorb --and-rebase` for auto-folding, or `git reset --soft HEAD~N && git commit` for squashing.".to_string(),
                });
            }
            None
        }
        "diff" | "show" | "log" => {
            // Using paged/colored/side-by-side diff output in agent context wastes tokens.
            let uses_pager_diff = cmd
                .args
                .iter()
                .any(|a| a == "--color=always" || a == "--color" || a == "--ext-diff");
            if uses_pager_diff {
                let alias = match subcommand {
                    "diff" => "adiff",
                    "show" => "ashow",
                    "log" => "alog",
                    _ => "",
                };
                let raw = format!(
                    "git -c core.pager= -c color.ui=false {} --no-ext-diff --no-color",
                    subcommand
                );
                let suggestion = if !alias.is_empty() {
                    git_alias_or_raw(alias, &raw)
                } else {
                    raw
                };
                return Some(ModernHint {
                    legacy_command: "git",
                    modern_command: "git",
                    hint: format!(
                        "For agent-safe output, use `{suggestion}`. Colored/paged/ext-diff output wastes tokens."
                    ),
                });
            }
            None
        }
        "push" => {
            // Force push warning
            if cmd.args.iter().any(|a| a == "--force" || a == "-f") {
                let targets_main = cmd.args.iter().any(|a| a == "main" || a == "master");
                if targets_main {
                    return Some(ModernHint {
                        legacy_command: "git",
                        modern_command: "git",
                        hint: "Never force push to main/master. Use `--force-with-lease` on feature branches if needed.".to_string(),
                    });
                }
            }
            None
        }
        _ => None,
    }
}

/// Format hints as a single context string for Claude.
pub fn format_hints(hints: &[ModernHint]) -> String {
    if hints.is_empty() {
        return String::new();
    }

    hints
        .iter()
        .map(|h| h.hint.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(program: &str, args: &[&str]) -> CommandInfo {
        CommandInfo {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            raw: format!("{} {}", program, args.join(" ")),
        }
    }

    // Tests call hint_* functions directly to avoid dependency on installed tools.
    // get_modern_hint() filters by tool availability which varies by environment.

    #[test]
    fn test_cat_hint() {
        let hint = hint_cat(&cmd("cat", &["file.rs"]));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.modern_command, "bat");
        assert!(hint.hint.contains("syntax highlighting"));
    }

    #[test]
    fn test_cat_no_file_no_hint() {
        // cat without a file is pipe usage - no hint
        let hint = hint_cat(&cmd("cat", &[]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_head_hint() {
        let hint = hint_head(&cmd("head", &["-n", "50", "file.txt"]));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.modern_command, "bat");
        assert!(hint.hint.contains("-r :50"));
    }

    #[test]
    fn test_head_no_file_no_hint() {
        // head without a file is pipe usage - no hint
        let hint = hint_head(&cmd("head", &["-n", "10"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_tail_no_file_no_hint() {
        // tail without a file is pipe usage - no hint
        let hint = hint_tail(&cmd("tail", &["-n", "10"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_tail_hint() {
        let hint = hint_tail(&cmd("tail", &["-n", "30", "file.txt"]));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert!(hint.hint.contains("-r -30:"));
    }

    #[test]
    fn test_tail_follow_no_hint() {
        // tail -f doesn't get a hint - it's the right tool for the job
        let hint = hint_tail(&cmd("tail", &["-f", "file.txt"]));
        assert!(hint.is_none(), "tail -f should not get a hint");
    }

    #[test]
    fn test_grep_hint() {
        let hint = hint_grep(&cmd("grep", &["-r", "pattern", "logs/"]));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.modern_command, "rg");
        assert!(hint.hint.contains("Recursive by default"));
    }

    #[test]
    fn test_grep_code_hint_prefers_sg() {
        let hint = hint_grep(&cmd("grep", &["-r", "handleAuth(", "src/"]));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.modern_command, "sg");
        assert!(hint.hint.contains("AST-aware"));
    }

    #[test]
    fn test_find_hint() {
        let hint = hint_find(&cmd("find", &[".", "-name", "*.rs"]));
        assert!(hint.hint.contains("fd *.rs ."));
    }

    #[test]
    fn test_find_hint_with_type_rewrite() {
        let hint = hint_find(&cmd("find", &[".", "-type", "f", "-name", "*.rs"]));
        assert!(hint.hint.contains("fd -t f *.rs ."));
    }

    #[test]
    fn test_sed_subst_hint() {
        let hint = hint_sed(&cmd("sed", &["-i", "s/old/new/g", "file.txt"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("sd"));
    }

    #[test]
    fn test_ls_simple_no_hint() {
        let hint = hint_ls(&cmd("ls", &[]));
        assert!(hint.is_none()); // Simple ls doesn't need hint
    }

    #[test]
    fn test_ls_detailed_hint() {
        let hint = hint_ls(&cmd("ls", &["-la"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("eza"));
    }

    #[test]
    fn test_ls_help_no_hint() {
        // --help should not trigger hint (regression test for flag detection)
        let hint = hint_ls(&cmd("ls", &["--help"]));
        assert!(hint.is_none(), "ls --help should not get a hint");
    }

    #[test]
    fn test_du_summary_no_hint() {
        // du -sh is a quick summary - no hint
        let hint = hint_du(&cmd("du", &["-sh", "."]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_du_recursive_hint() {
        let hint = hint_du(&cmd("du", &["-h", "."]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("dust"));
    }

    #[test]
    fn test_tokei_hint() {
        let hint = hint_cloc(&cmd("cloc", &["."]));
        assert!(hint.hint.contains("tokei"));
    }

    #[test]
    fn test_unknown_command_no_hint() {
        // This tests get_modern_hint's matching logic (unknown commands not handled)
        let hint = get_modern_hint(&cmd("rustfmt", &["file.rs"]));
        assert!(hint.is_none());
    }

    // === Anti-pattern tests ===

    #[test]
    fn test_bat_bad_flags() {
        let hint = hint_bat_flags(&cmd("bat", &["--style=plain", "file.rs"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("no-ops"));
    }

    #[test]
    fn test_bat_plain_flag() {
        let hint = hint_bat_flags(&cmd("bat", &["-p", "file.rs"]));
        assert!(hint.is_some());
    }

    #[test]
    fn test_bat_good_flags_no_hint() {
        let hint = hint_bat_flags(&cmd("bat", &["-r", "10:20", "file.rs"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_bat_no_flags_no_hint() {
        let hint = hint_bat_flags(&cmd("bat", &["file.rs"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_rg_body_capture_hint() {
        let hint = hint_rg_body_capture(&cmd("rg", &["-A20", "function handleAuth", "src/"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("sg"));
    }

    #[test]
    fn test_rg_context_on_logs_no_hint() {
        // rg -A on non-code targets is fine
        let hint = hint_rg_body_capture(&cmd("rg", &["-A5", "ERROR", "logs/"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_git_status_uall_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["status", "-uall"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("memory"));
    }

    #[test]
    fn test_git_status_normal_no_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["status"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_git_add_all_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["add", "-A"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("specific files"));
    }

    #[test]
    fn test_git_add_dot_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["add", "."]));
        assert!(hint.is_some());
    }

    #[test]
    fn test_git_add_specific_no_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["add", "src/main.rs"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_git_commit_no_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["commit", "-m", "fix: thing"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_git_add_patch_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["add", "-p"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("grepdiff"));
    }

    #[test]
    fn test_git_add_interactive_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["add", "-i"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("hangs agent"));
    }

    #[test]
    fn test_git_rebase_interactive_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["rebase", "-i", "HEAD~3"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("hangs agent"));
    }

    #[test]
    fn test_git_rebase_non_interactive_no_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["rebase", "main"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_git_diff_color_always_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["diff", "--color=always"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("agent-safe"));
    }

    #[test]
    fn test_git_show_ext_diff_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["show", "--ext-diff"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("wastes tokens"));
    }

    #[test]
    fn test_git_diff_plain_no_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["diff"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_git_push_force_main_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["push", "--force", "origin", "main"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("Never force push"));
    }

    #[test]
    fn test_git_push_force_branch_no_hint() {
        let hint = hint_git_antipatterns(&cmd(
            "git",
            &["push", "--force", "origin", "feature-branch"],
        ));
        assert!(hint.is_none());
    }
}

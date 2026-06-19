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

/// One catalog entry describing a legacy -> modern tool pairing, for the docs
/// generator and the "Modern CLI hints" reference page.
///
/// This is a documentation-facing summary of the runtime hint families in this
/// module. It is intentionally decoupled from [`get_modern_hint`] (which parses
/// args, checks config, and gates on tool availability): the catalog is a flat
/// static list with no I/O, so consuming it cannot change runtime behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HintCatalogEntry {
    /// The legacy invocation as shown to a reader, e.g. `"cat"`, `"grep -r"`,
    /// `"find . -name"`. May include a representative flag for context.
    pub legacy: &'static str,
    /// The modern replacement command, e.g. `"bat"`, `"rg"`, `"fd"`.
    pub modern: &'static str,
    /// One short clause explaining why the modern tool is preferred.
    pub why: &'static str,
    /// When `Some(program)`, this pairing is an unconditional substitute keyed
    /// on the bare program name, so the docs generator can surface it on that
    /// program's allow row. `None` marks flag- or subcommand-conditional
    /// pairings (e.g. `grep` -> rg/sg by pattern shape) that the generator
    /// leaves off allow rows.
    pub program_level: Option<&'static str>,
}

/// The full modern-CLI hint catalog, in display order for the reference page.
///
/// Ordered by category (file viewing, search/find, text, listing/disk, process,
/// network, archives, language tooling, DNS) to mirror how the families appear
/// in this module. Stable order keeps the generated reference page and any
/// allow-row surfacing byte-identical on re-run.
///
/// Anti-pattern self-hints (`bat` bad flags, `rg` on code, `git` interactive
/// staging) are not legacy->modern pairings and are deliberately omitted.
pub fn hint_catalog() -> &'static [HintCatalogEntry] {
    const C: &[HintCatalogEntry] = &[
        // File viewing
        HintCatalogEntry {
            legacy: "cat",
            modern: "bat",
            why: "Line-numbered, syntax-highlighted output; precise follow-up edits.",
            program_level: Some("cat"),
        },
        HintCatalogEntry {
            legacy: "less",
            modern: "bat",
            why: "Paged, line-numbered viewing without a separate pager.",
            program_level: Some("less"),
        },
        HintCatalogEntry {
            legacy: "more",
            modern: "bat",
            why: "Paged, line-numbered viewing without a separate pager.",
            program_level: Some("more"),
        },
        HintCatalogEntry {
            legacy: "head -n N <file>",
            modern: "bat -r :N",
            why: "Arbitrary line ranges, not just first-N, with line numbers.",
            program_level: None,
        },
        HintCatalogEntry {
            legacy: "tail -n N <file>",
            modern: "bat -r -N:",
            why: "Arbitrary line ranges, not just last-N, with line numbers.",
            program_level: None,
        },
        // Search & find
        HintCatalogEntry {
            legacy: "grep",
            modern: "rg",
            why: "Recursive by default, respects .gitignore, faster on large trees.",
            program_level: None,
        },
        HintCatalogEntry {
            legacy: "ag / ack",
            modern: "rg",
            why: "Faster with a similar interface.",
            program_level: Some("ag"),
        },
        HintCatalogEntry {
            legacy: "find",
            modern: "fd",
            why: "Shorter syntax, .gitignore-aware, faster.",
            program_level: Some("find"),
        },
        // Text processing
        HintCatalogEntry {
            legacy: "sed s/.../.../",
            modern: "sd",
            why: "Plain find/replace, no s/.../.../g escaping.",
            program_level: None,
        },
        HintCatalogEntry {
            legacy: "awk '{print $N}'",
            modern: "choose",
            why: "Field selection routes to choose; column sums to jq; line counts to rg -c; byte math to numbat; positional row/field to jc.",
            program_level: None,
        },
        HintCatalogEntry {
            legacy: "wc -l <file>",
            modern: "rg -c '.'",
            why: "Counts lines without a separate utility (piped wc -l is fine).",
            program_level: None,
        },
        // File listing & disk
        HintCatalogEntry {
            legacy: "ls -la",
            modern: "eza -la",
            why: "Git status integration and clearer formatting.",
            program_level: None,
        },
        HintCatalogEntry {
            legacy: "du",
            modern: "dust",
            why: "Visual disk-usage tree (du -sh summaries are fine).",
            program_level: None,
        },
        HintCatalogEntry {
            legacy: "tree",
            modern: "eza -T",
            why: "Git status integration and clearer formatting.",
            program_level: Some("tree"),
        },
        // Process inspection
        HintCatalogEntry {
            legacy: "ps aux",
            modern: "procs",
            why: "Readable columns and a tree view.",
            program_level: None,
        },
        // Network
        HintCatalogEntry {
            legacy: "curl <github-url>",
            modern: "gh api",
            why: "Preserves auth, rate limits, and private-repo access.",
            program_level: None,
        },
        HintCatalogEntry {
            legacy: "wget <github-url>",
            modern: "gh api",
            why: "Preserves auth, rate limits, and private-repo access.",
            program_level: None,
        },
        // Diff & hex
        HintCatalogEntry {
            legacy: "diff <a> <b>",
            modern: "difft",
            why: "Syntax-aware diffs (git diff for unified patches).",
            program_level: None,
        },
        HintCatalogEntry {
            legacy: "xxd / hexdump",
            modern: "hexyl",
            why: "Colored, readable hex output.",
            program_level: Some("xxd"),
        },
        // Code stats
        HintCatalogEntry {
            legacy: "cloc",
            modern: "tokei",
            why: "Faster with clearer formatting.",
            program_level: Some("cloc"),
        },
        // Documentation
        HintCatalogEntry {
            legacy: "man",
            modern: "tldr",
            why: "Practical examples, concise output.",
            program_level: Some("man"),
        },
        // Python tooling
        HintCatalogEntry {
            legacy: "pip install",
            modern: "uv pip",
            why: "Faster, lockfile-aware, cache-shared.",
            program_level: Some("pip"),
        },
        HintCatalogEntry {
            legacy: "python -m venv",
            modern: "uv venv",
            why: "Faster; picks up the project's Python pin.",
            program_level: None,
        },
        // DNS
        HintCatalogEntry {
            legacy: "dig / nslookup",
            modern: "doggo",
            why: "Colored output, JSON with --json, modern defaults.",
            program_level: Some("dig"),
        },
        // Archives
        HintCatalogEntry {
            legacy: "unzip",
            modern: "ouch decompress",
            why: "Format-agnostic (zip/tar/gz/xz/7z), auto-detects.",
            program_level: Some("unzip"),
        },
        HintCatalogEntry {
            legacy: "zip",
            modern: "ouch compress",
            why: "Format inferred from the output extension.",
            program_level: None,
        },
        HintCatalogEntry {
            legacy: "tar -x",
            modern: "ouch decompress",
            why: "Format-agnostic, auto-detects compression (create with tar -c).",
            program_level: None,
        },
    ];
    C
}

/// Look up the unconditional program-level hint for a bare program name, if one
/// exists. Returns `None` for programs whose modern alternative is flag- or
/// subcommand-conditional (those are not surfaced on allow rows).
///
/// Aliases that share a single catalog entry (`pip3` -> the `pip` entry,
/// `nslookup` -> the `dig` entry, `hexdump` -> the `xxd` entry, `ack` -> the
/// `ag` entry) resolve to the same row via the alias map below.
pub fn program_hint(program: &str) -> Option<&'static HintCatalogEntry> {
    // Aliases collapse to the catalog's canonical program key so a single entry
    // covers the family.
    let canonical = match program {
        "pip3" => "pip",
        "nslookup" => "dig",
        "hexdump" => "xxd",
        "ack" => "ag",
        other => other,
    };
    hint_catalog()
        .iter()
        .find(|e| e.program_level == Some(canonical))
}

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
        "http" | "https" | "xh" => hint_httpie(cmd),
        // Diff & hex (code understanding)
        "diff" => hint_diff(cmd),
        "xxd" | "hexdump" => Some(hint_hex(cmd)),
        // Code stats
        "cloc" => Some(hint_cloc(cmd)),
        // Documentation (understanding APIs/libraries)
        "man" => hint_man(cmd),
        // Python tooling
        "pip" | "pip3" => Some(hint_pip(cmd)),
        "python" | "python3" => hint_python(cmd),
        // DNS
        "dig" | "nslookup" => Some(hint_dns(cmd)),
        // Archives
        "unzip" => Some(hint_unzip(cmd)),
        "zip" => hint_zip(cmd),
        "tar" => hint_tar(cmd),
        // Anti-patterns (bad flags, wrong tool for job)
        "bat" => hint_bat_flags(cmd),
        "rg" => hint_rg_on_code(cmd),
        "git" => hint_git_antipatterns(cmd),
        _ => None,
    }?;

    // Only return hint if the modern tool is installed.
    //
    // The on-disk cache has a TTL (default 7 days). If a user installs a
    // modern tool today, hints would stay silent until the cache rolls.
    // When the cache says missing, opportunistically re-probe just this
    // one tool. The result is memoized for the rest of this process and
    // written back to the disk cache so other processes see it too.
    let available = cache().is_available(hint.modern_command)
        || crate::tool_cache::refresh_tool(hint.modern_command);
    if available { Some(hint) } else { None }
}

fn hint_cat(cmd: &CommandInfo) -> Option<ModernHint> {
    let files: Vec<_> = cmd.args.iter().filter(|a| !a.starts_with('-')).collect();
    // No file argument means pipe usage (echo | cat) - no hint needed
    if files.is_empty() {
        return None;
    }

    let file = files[0];

    Some(ModernHint {
        legacy_command: "cat",
        modern_command: "bat",
        hint: format!("Use Read to view `{file}`. `bat {file}` only if piping/redirecting."),
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

    // Pipe usage (command | head): the head/tail deny path hard-blocks only
    // build/gh producers; low-harm caps pass through. Ride a self-correct hint
    // so the next call caps at the source instead of truncating the stream.
    if file.is_empty() {
        return Some(ModernHint {
            legacy_command: "head",
            modern_command: "rg",
            hint: "Cap at the source, don't truncate the pipe: `rg -m N`, `--limit N`, \
                   `git log -n N`, or `sort -rn | head -N` for top-N. Use Read for files."
                .to_string(),
        });
    }

    let bat_range = format!(":{}", lines);
    Some(ModernHint {
        legacy_command: "head",
        modern_command: "bat",
        hint: format!(
            "Use Read to view `{file}`. `bat -r {bat_range} {file}` only if piping the slice."
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

    // tail -f is fine - no hint needed (it's the streaming/Monitor case)
    if follow {
        return None;
    }

    // Pipe usage (command | tail): mirror hint_head. Low-harm caps pass through
    // the deny path; ride a self-correct hint toward a source-side cap.
    if file.is_empty() {
        return Some(ModernHint {
            legacy_command: "tail",
            modern_command: "rg",
            hint: "Cap at the source, don't truncate the pipe: `rg -m N`, `--limit N`, \
                   `git log -n N`, or `sort -rn | tail -N` for bottom-N. Use Read for files; \
                   live logs via `tail -f` through the Monitor tool."
                .to_string(),
        });
    }

    let bat_range = format!("-{}:", lines);
    Some(ModernHint {
        legacy_command: "tail",
        modern_command: "bat",
        hint: format!(
            "Use Read to view `{file}`. `bat -r {bat_range} {file}` only if piping the slice."
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
        looks_like_code_pattern(pattern) || targets.iter().any(|t| is_strict_code_target(t));
    if code_search {
        let has_context = cmd
            .args
            .iter()
            .any(|a| a.starts_with("-A") || a.starts_with("-B") || a.starts_with("-C"));
        return Some(ModernHint {
            legacy_command: "grep",
            modern_command: "sg",
            hint: code_search_hint_text(pattern, has_context),
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
    // GitHub-hosted content - nudge toward `gh api` regardless of other flags.
    // Fires even when the gate ends up allowing (e.g. HEAD requests), so the
    // next invocation of a similar shape learns the better pattern.
    if cmd.args.iter().any(|a| {
        let s = a.trim_matches(|c| c == '"' || c == '\'');
        (s.starts_with("http://") || s.starts_with("https://"))
            && crate::gates::helpers::is_github_content_url(s)
    }) {
        return Some(ModernHint {
            legacy_command: "curl",
            modern_command: "gh",
            hint:
                "Use `gh api repos/OWNER/REPO/contents/PATH` (or `gh release download TAG` for release assets) instead of `curl` for GitHub content. Preserves auth, rate limits, and private-repo access."
                    .to_string(),
        });
    }

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
    // GitHub-hosted content - same nudge as curl.
    if cmd.args.iter().any(|a| {
        let s = a.trim_matches(|c| c == '"' || c == '\'');
        (s.starts_with("http://") || s.starts_with("https://"))
            && crate::gates::helpers::is_github_content_url(s)
    }) {
        return Some(ModernHint {
            legacy_command: "wget",
            modern_command: "gh",
            hint:
                "Use `gh api repos/OWNER/REPO/contents/PATH` (or `gh release download TAG` for release assets) instead of `wget` for GitHub content. Preserves auth, rate limits, and private-repo access."
                    .to_string(),
        });
    }

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

fn hint_httpie(cmd: &CommandInfo) -> Option<ModernHint> {
    // Only hint when a GitHub content URL is in args. Plain HTTPie calls are
    // already fine and don't need a nudge.
    if !cmd.args.iter().any(|a| {
        let s = a.trim_matches(|c| c == '"' || c == '\'');
        (s.starts_with("http://") || s.starts_with("https://"))
            && crate::gates::helpers::is_github_content_url(s)
    }) {
        return None;
    }

    let legacy: &'static str = match cmd.program.as_str() {
        "http" => "http",
        "https" => "https",
        _ => "xh",
    };

    Some(ModernHint {
        legacy_command: legacy,
        modern_command: "gh",
        hint:
            "Use `gh api repos/OWNER/REPO/contents/PATH` (or `gh release download TAG` for release assets) instead for GitHub content. Preserves auth, rate limits, and private-repo access."
                .to_string(),
    })
}

fn hint_awk(cmd: &CommandInfo) -> Option<ModernHint> {
    // The awk program text (and any flags) live in args; join once so multi-token
    // idioms like `END{print NR}` survive substring checks.
    let prog = cmd.args.join(" ");
    let has_sum = prog.contains("+=");
    let has_unit_div = ["/1024", "/1048576", "/1073741824", "/1000000"]
        .iter()
        .any(|d| prog.contains(d));
    let has_print_field = prog.contains("print $");

    // Byte/size arithmetic -> numbat (unit-aware). When the program also sums a
    // column, numbat alone won't reduce it, so point at jq for the reduction too.
    if has_unit_div {
        let hint = if has_sum {
            "Use `numbat` for byte/size math (e.g. `numbat '12884901888 bytes -> GB'`); reduce the column first with `jq -Rn '[inputs|tonumber]|add'`. Avoids awk printf division."
        } else {
            "Use `numbat` for byte/size math, e.g. `numbat '12884901888 bytes -> GB'`, instead of awk printf division."
        };
        return Some(ModernHint {
            legacy_command: "awk",
            modern_command: "numbat",
            hint: hint.to_string(),
        });
    }

    // Column reduction (sum) -> jq slurp. No autoapproved peer does stream math;
    // `jq -Rn` reads raw lines and adds them.
    if has_sum {
        return Some(ModernHint {
            legacy_command: "awk",
            modern_command: "jq",
            hint: "Sum a column with `... | jq -Rn '[inputs|tonumber]|add'` instead of awk '{s+=$1} END{print s}'.".to_string(),
        });
    }

    // Line count (END{print NR}, no field refs) -> rg -c.
    if prog.contains("NR") && prog.contains("END") && !prog.contains('$') {
        return Some(ModernHint {
            legacy_command: "awk",
            modern_command: "rg",
            hint: "Count lines with `rg -c '.' <file>` instead of awk 'END{print NR}'.".to_string(),
        });
    }

    // Positional row+field from tabular command output -> jc | jq. Robust to
    // column shifts, unlike awk's NR/$N indexing.
    if prog.contains("NR==") && has_print_field {
        return Some(ModernHint {
            legacy_command: "awk",
            modern_command: "jc",
            hint: "Extract a row/field from structured command output with `<cmd> | jc --<parser> | jq` (robust to column shifts), e.g. `df / | jc --df | jq '.[0].available'`, instead of awk NR/$N indexing.".to_string(),
        });
    }

    // Plain field selection -> choose.
    if has_print_field {
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
        hint: format!(
            "Use `hexyl <file>` instead of `{legacy}`. Colored output, better formatting."
        ),
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
        hint: "Use `bat <file>` instead of `less`. Line-numbered output makes follow-up `Edit` and `Read` calls target specific lines precisely."
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
            "bat flag(s) {} are no-ops or counterproductive in agent piped output. Only `-r START:END` (line range) and `-A` (show whitespace) work as expected. For straight file viewing, use `bat <file>` without extra flags.",
            used_bad.join(", ")
        ),
    })
}

/// Strict code-target check matching the system-prompt rule "NEVER use rg on
/// code files". Only programming-language source files and code directories
/// count as "code". Configs (.yaml/.toml/.json), docs (.md), and logs are
/// non-code per the rule and rg is fine on them.
fn is_strict_code_target(target: &str) -> bool {
    let lower = target
        .trim_matches(|c| c == '"' || c == '\'')
        .to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }

    const CODE_EXTENSIONS: &[&str] = &[
        ".rs", ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt", ".kts", ".c", ".h",
        ".cpp", ".hpp", ".cs", ".rb", ".php", ".swift", ".scala", ".sh", ".bash", ".zsh",
    ];

    if let Some(dot) = lower.rfind('.') {
        let ext = &lower[dot..];
        return CODE_EXTENSIONS.contains(&ext);
    }

    const CODE_DIRS: &[&str] = &[
        "src", "lib", "app", "pkg", "cmd", "internal", "tests", "test", "spec", "crates",
        "include", "examples",
    ];
    let stripped = lower.trim_start_matches("./").trim_end_matches('/');
    CODE_DIRS.iter().any(|d| {
        stripped == *d
            || stripped.starts_with(&format!("{d}/"))
            || stripped.contains(&format!("/{d}/"))
    })
}

/// Pure-identifier shape (camelCase, snake_case, PascalCase). No spaces, no
/// regex metacharacters, no quotes. Single token only.
fn is_identifier_shape(pattern: &str) -> bool {
    let trimmed = pattern.trim_matches(|c| c == '"' || c == '\'');
    if trimmed.is_empty() {
        return false;
    }
    let mut chars = trimmed.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Natural-language shape: 3+ alphabetic words separated by spaces, no regex
/// metacharacters or special chars. Heuristic for "the user is asking a
/// conceptual question, route to ChunkHound semantic".
fn is_natural_language_shape(pattern: &str) -> bool {
    let trimmed = pattern.trim_matches(|c| c == '"' || c == '\'');
    if trimmed.len() < 8 {
        return false;
    }
    // Reject regex / shell special chars
    if trimmed.chars().any(|c| {
        matches!(
            c,
            '(' | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '\\'
                | '|'
                | '*'
                | '+'
                | '?'
                | '$'
                | '^'
                | '<'
                | '>'
                | '='
        )
    }) {
        return false;
    }
    let words: Vec<&str> = trimmed.split_whitespace().collect();
    if words.len() < 3 {
        return false;
    }
    words.iter().all(|w| {
        w.chars()
            .all(|c| c.is_ascii_alphabetic() || c == '-' || c == '\'')
    })
}

/// Build the right hint for a code-targeted grep/rg invocation, routing to
/// Probe/ChunkHound/Serena/sg per /etc/claude-code/system-prompt.md.
fn code_search_hint_text(pattern: &str, has_context_flag: bool) -> String {
    if has_context_flag {
        return "Use `sg -p 'pattern' src/` instead of `rg -A`/`-B`/`-C` for capturing function/class bodies. AST-aware matching gives exact boundaries.".to_string();
    }

    if is_identifier_shape(pattern) {
        return "Don't `rg` on code. For exact symbol lookup use `mcp__probe__search_code` with `exact: true`; for navigation (definitions, references), `mcp__serena__find_symbol`.".to_string();
    }

    if looks_like_code_pattern(pattern) || pattern.contains('(') || pattern.contains('{') {
        return "Don't `rg` on code. For structural patterns use `sg -p '<pattern>' src/` (AST-aware, supports `$VAR` metavars).".to_string();
    }

    if is_natural_language_shape(pattern) {
        return "Don't `rg` on code. For conceptual queries use `mcp__chunkhound__search` (`type: \"semantic\"`); `code_research` for cross-file flows.".to_string();
    }

    "Don't `rg` on code. Use `mcp__probe__search_code` (known terms), `mcp__chunkhound__search` (conceptual), `mcp__serena__find_symbol` (symbols), or `sg -p` (structural). `rg` is for non-code text only.".to_string()
}

fn hint_rg_on_code(cmd: &CommandInfo) -> Option<ModernHint> {
    if cmd.args.is_empty() {
        return None;
    }

    // Extract non-flag args (pattern first, then targets).
    let mut non_flag: Vec<&str> = Vec::new();
    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-e" | "--regexp" | "-f" | "--file" | "-g" | "--glob" | "-t" | "--type" => {
                // Skip the flag's value.
                iter.next();
            }
            a if !a.starts_with('-') => non_flag.push(a),
            _ => {}
        }
    }

    let pattern = non_flag.first().copied().unwrap_or("");
    let targets = if non_flag.len() > 1 {
        &non_flag[1..]
    } else {
        &[][..]
    };

    // Fire when any target is a code file or code directory. Pattern-only
    // detection (e.g. searching for `function foo` in any path) routes through
    // hint_grep already; here we focus on the target check that matches the
    // strict "NEVER use rg on code files" rule.
    let targets_code = targets.iter().any(|t| is_strict_code_target(t));
    if !targets_code {
        return None;
    }

    let has_context_flag = cmd.args.iter().any(|a| {
        let s = a.as_str();
        s == "-A"
            || s == "-B"
            || s == "-C"
            || (s.starts_with("-A") && s.len() > 2 && s[2..].chars().all(|c| c.is_ascii_digit()))
            || (s.starts_with("-B") && s.len() > 2 && s[2..].chars().all(|c| c.is_ascii_digit()))
            || (s.starts_with("-C") && s.len() > 2 && s[2..].chars().all(|c| c.is_ascii_digit()))
    });

    Some(ModernHint {
        legacy_command: "rg",
        modern_command: "sg",
        hint: code_search_hint_text(pattern, has_context_flag),
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
                    hint: "Avoid `git status -uall` on large repos (memory issues). Use `git status` without `-uall`.".to_string(),
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
                return Some(ModernHint {
                    legacy_command: "git",
                    modern_command: "git",
                    hint: "Never use `git add -p` or `git add -i` (interactive, hangs the agent). Use the `git-history-and-staging` skill for surgical staging recipes."
                        .to_string(),
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

// === Python tooling hints ===

fn hint_pip(cmd: &CommandInfo) -> ModernHint {
    let subcommand = cmd.args.iter().find(|a| !a.starts_with('-'));
    let hint = match subcommand.map(String::as_str) {
        Some("install") => {
            "Use `uv pip install` (or `uv add` for project deps) instead of `pip install`. Faster, lockfile-aware, cache-shared."
        }
        Some("uninstall") => {
            "Use `uv pip uninstall` instead of `pip uninstall`. Drop-in replacement, faster."
        }
        Some("list") | Some("freeze") | Some("show") => {
            "Use `uv pip` instead of `pip` for inspection. Same subcommands, faster."
        }
        _ => {
            "Use `uv pip` instead of `pip` (or `uv add`/`uv sync` for project deps). Faster, lockfile-aware."
        }
    };
    ModernHint {
        legacy_command: if cmd.program == "pip3" { "pip3" } else { "pip" },
        modern_command: "uv",
        hint: hint.to_string(),
    }
}

fn hint_python(cmd: &CommandInfo) -> Option<ModernHint> {
    // Only hint for `python -m pip ...` or `python -m venv ...`. Bare
    // `python script.py` is fine and has no uv equivalent.
    let m_target = cmd
        .args
        .windows(2)
        .find(|w| w[0] == "-m")
        .map(|w| w[1].as_str())?;

    let hint = match m_target {
        "pip" => "Use `uv pip <subcommand>` instead of `python -m pip`. Faster, lockfile-aware.",
        "venv" => {
            "Use `uv venv` instead of `python -m venv`. Faster, picks up your project's Python pin."
        }
        _ => return None,
    };

    Some(ModernHint {
        legacy_command: if cmd.program == "python3" {
            "python3"
        } else {
            "python"
        },
        modern_command: "uv",
        hint: hint.to_string(),
    })
}

// === DNS hints ===

fn hint_dns(cmd: &CommandInfo) -> ModernHint {
    let legacy = if cmd.program == "nslookup" {
        "nslookup"
    } else {
        "dig"
    };
    ModernHint {
        legacy_command: legacy,
        modern_command: "doggo",
        hint: format!(
            "Use `doggo <name>` instead of `{}`. Colored output, structured JSON with `--json`, modern defaults.",
            legacy
        ),
    }
}

// === Archive hints ===

fn hint_unzip(_cmd: &CommandInfo) -> ModernHint {
    ModernHint {
        legacy_command: "unzip",
        modern_command: "ouch",
        hint: "Use `ouch decompress <file.zip>` instead of `unzip`. Format-agnostic (zip/tar/gz/xz/7z), auto-detects.".to_string(),
    }
}

fn hint_zip(cmd: &CommandInfo) -> Option<ModernHint> {
    // `zip --version` and similar info queries don't need a hint
    let has_positional = cmd.args.iter().any(|a| !a.starts_with('-'));
    if !has_positional {
        return None;
    }
    Some(ModernHint {
        legacy_command: "zip",
        modern_command: "ouch",
        hint: "Use `ouch compress <inputs...> <out.zip>` instead of `zip`. Format inferred from extension.".to_string(),
    })
}

fn hint_tar(cmd: &CommandInfo) -> Option<ModernHint> {
    // Treat short-option bundles like `-xzf` / `xzf` as a single flag token.
    // Only extract usage gets the hint; create (`-c`) stays useful for
    // streaming pipelines that ouch can't replicate cleanly.
    let mut extract = false;
    let mut create = false;
    for arg in &cmd.args {
        if arg == "--extract" || arg == "--get" {
            extract = true;
        } else if arg == "--create" {
            create = true;
        } else if arg.starts_with('-') && !arg.starts_with("--") {
            let flags = &arg[1..];
            if flags.contains('x') {
                extract = true;
            }
            if flags.contains('c') {
                create = true;
            }
        } else if !arg.contains('/') && !arg.contains('.') && arg.len() <= 4 {
            // Bare short-bundle like `xzf` or `czvf` (no leading dash, BSD tar style).
            if arg.contains('x') {
                extract = true;
            }
            if arg.contains('c') {
                create = true;
            }
        }
    }

    if extract && !create {
        return Some(ModernHint {
            legacy_command: "tar",
            modern_command: "ouch",
            hint: "Use `ouch decompress <archive>` instead of `tar -x`. Format-agnostic, auto-detects compression.".to_string(),
        });
    }
    None
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

/// Compute and format modern-CLI hints for a raw shell command.
///
/// Used by the Codex PostToolUse path where hints are deferred because
/// non-deny PreToolUse decisions serialize to empty stdout. Independent of
/// gate-decision logic so it can run on any successful command without rerunning
/// the full router.
pub fn compute_hints_for_command(command: &str, session_id: &str) -> String {
    if command.is_empty() {
        return String::new();
    }
    let commands = crate::parser::extract_commands(command);
    let mut hints: Vec<ModernHint> = Vec::new();
    for cmd in &commands {
        if let Some(hint) = get_modern_hint(cmd) {
            hints.push(hint);
        }
    }
    crate::hint_tracker::filter_hints(session_id, &mut hints);
    format_hints(&hints)
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
        // Read-first: the Read tool is preferred over a Bash `bat` slice.
        assert!(hint.hint.contains("Read"));
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
    fn test_head_pipe_self_correct_hint() {
        // head on a pipe (no file) rides a self-correct hint toward a
        // source-side cap instead of staying silent.
        let hint = hint_head(&cmd("head", &["-n", "10"])).expect("pipe head should hint");
        assert_eq!(hint.modern_command, "rg");
        assert!(hint.hint.contains("rg -m N") && hint.hint.contains("Read"));
    }

    #[test]
    fn test_tail_pipe_self_correct_hint() {
        let hint = hint_tail(&cmd("tail", &["-n", "10"])).expect("pipe tail should hint");
        assert_eq!(hint.modern_command, "rg");
        assert!(hint.hint.contains("rg -m N") && hint.hint.contains("Read"));
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
        // Pattern has `(` so routes to structural hint mentioning sg + metavars
        assert!(
            hint.hint.contains("sg -p"),
            "expected sg suggestion, got: {}",
            hint.hint
        );
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
    fn test_awk_field_extraction_routes_to_choose() {
        let hint = hint_awk(&cmd("awk", &["{print $1}"])).unwrap();
        assert_eq!(hint.modern_command, "choose");
    }

    #[test]
    fn test_awk_sum_routes_to_jq() {
        let hint = hint_awk(&cmd("awk", &["{s+=$1} END{print s}"])).unwrap();
        assert_eq!(hint.modern_command, "jq");
        assert!(hint.hint.contains("jq -Rn"), "got: {}", hint.hint);
    }

    #[test]
    fn test_awk_byte_math_routes_to_numbat() {
        let hint = hint_awk(&cmd("awk", &["{printf \"%.1f GB\", $1/1073741824}"])).unwrap();
        assert_eq!(hint.modern_command, "numbat");
    }

    #[test]
    fn test_awk_sum_with_unit_division_prefers_numbat_and_mentions_jq() {
        let hint = hint_awk(&cmd(
            "awk",
            &["{sum+=$1} END {printf \"%.1f GB\", sum/1073741824}"],
        ))
        .unwrap();
        assert_eq!(hint.modern_command, "numbat");
        assert!(hint.hint.contains("jq -Rn"), "got: {}", hint.hint);
    }

    #[test]
    fn test_awk_line_count_routes_to_rg() {
        let hint = hint_awk(&cmd("awk", &["END{print NR}"])).unwrap();
        assert_eq!(hint.modern_command, "rg");
        assert!(hint.hint.contains("rg -c"), "got: {}", hint.hint);
    }

    #[test]
    fn test_awk_row_field_routes_to_jc() {
        let hint = hint_awk(&cmd("awk", &["NR==2{print $4}"])).unwrap();
        assert_eq!(hint.modern_command, "jc");
    }

    #[test]
    fn test_awk_range_extraction_no_hint() {
        // Stateful range extraction has no autoapproved peer, so it must not nudge.
        let hint = hint_awk(&cmd("awk", &["/^---$/{c++; next} c==1"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_awk_bare_filter_no_hint() {
        // A field-comparison filter with no print/sum/count idiom gets no hint.
        let hint = hint_awk(&cmd("awk", &["-F\t", "$2 > 5000"]));
        assert!(hint.is_none());
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
        // rg -A on a code dir suggests sg for body capture
        let hint = hint_rg_on_code(&cmd("rg", &["-A20", "function handleAuth", "src/"]));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.modern_command, "sg");
        assert!(
            hint.hint.contains("sg -p"),
            "expected sg body-capture hint, got: {}",
            hint.hint
        );
    }

    #[test]
    fn test_rg_context_on_logs_no_hint() {
        // rg -A on non-code targets is fine
        let hint = hint_rg_on_code(&cmd("rg", &["-A5", "ERROR", "logs/"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_rg_identifier_on_code_suggests_probe() {
        // Bare identifier on a code dir routes to probe + serena
        let hint = hint_rg_on_code(&cmd("rg", &["getUserById", "src/"]));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert!(
            hint.hint.contains("mcp__probe__search_code"),
            "expected probe suggestion, got: {}",
            hint.hint
        );
        assert!(
            hint.hint.contains("mcp__serena__find_symbol"),
            "expected serena suggestion, got: {}",
            hint.hint
        );
    }

    #[test]
    fn test_rg_natural_language_suggests_chunkhound() {
        // Multi-word English phrase on code routes to chunkhound semantic
        let hint = hint_rg_on_code(&cmd("rg", &["where authentication is handled", "src/"]));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert!(
            hint.hint.contains("mcp__chunkhound__search"),
            "expected chunkhound suggestion, got: {}",
            hint.hint
        );
    }

    #[test]
    fn test_rg_on_yaml_no_hint() {
        // YAML is config, not code. rg is fine here per the rule.
        let hint = hint_rg_on_code(&cmd("rg", &["redis_url", "config.yaml"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_rg_on_md_no_hint() {
        // Markdown is docs, not code.
        let hint = hint_rg_on_code(&cmd("rg", &["TODO", "README.md"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_rg_on_log_in_src_no_hint() {
        // src/app.log is a log file, not code, even though it's under src/.
        let hint = hint_rg_on_code(&cmd("rg", &["ERROR", "src/app.log"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_rg_on_rs_file_suggests_routing() {
        // Single .rs file is a code target
        let hint = hint_rg_on_code(&cmd("rg", &["fn main", "src/main.rs"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("sg -p"));
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
        assert!(hint.unwrap().hint.contains("git-history-and-staging"));
    }

    #[test]
    fn test_git_add_interactive_hint() {
        let hint = hint_git_antipatterns(&cmd("git", &["add", "-i"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("hangs the agent"));
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

    // === pip / python venv -> uv tests ===

    #[test]
    fn test_pip_install_hint() {
        let hint = hint_pip(&cmd("pip", &["install", "requests"]));
        assert_eq!(hint.modern_command, "uv");
        assert!(hint.hint.contains("uv pip install"));
    }

    #[test]
    fn test_pip3_install_hint_uses_legacy_name() {
        let hint = hint_pip(&cmd("pip3", &["install", "-r", "requirements.txt"]));
        assert_eq!(hint.legacy_command, "pip3");
        assert_eq!(hint.modern_command, "uv");
    }

    #[test]
    fn test_pip_list_hint() {
        let hint = hint_pip(&cmd("pip", &["list"]));
        assert!(hint.hint.contains("uv pip"));
    }

    #[test]
    fn test_python_m_pip_hint() {
        let hint = hint_python(&cmd("python3", &["-m", "pip", "install", "requests"]));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.modern_command, "uv");
        assert!(hint.hint.contains("uv pip"));
    }

    #[test]
    fn test_python_m_venv_hint() {
        let hint = hint_python(&cmd("python3", &["-m", "venv", ".venv"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("uv venv"));
    }

    #[test]
    fn test_python_script_no_hint() {
        // python script.py is fine, no uv equivalent
        let hint = hint_python(&cmd("python3", &["script.py", "--arg"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_python_m_pytest_no_hint() {
        // python -m pytest is a different concern (test runner, not pip)
        let hint = hint_python(&cmd("python3", &["-m", "pytest", "tests/"]));
        assert!(hint.is_none());
    }

    // === dig / nslookup -> doggo tests ===

    #[test]
    fn test_dig_hint() {
        let hint = hint_dns(&cmd("dig", &["example.com"]));
        assert_eq!(hint.legacy_command, "dig");
        assert_eq!(hint.modern_command, "doggo");
        assert!(hint.hint.contains("doggo"));
    }

    #[test]
    fn test_nslookup_hint() {
        let hint = hint_dns(&cmd("nslookup", &["example.com"]));
        assert_eq!(hint.legacy_command, "nslookup");
        assert!(hint.hint.contains("doggo"));
    }

    // === unzip / zip / tar -> ouch tests ===

    #[test]
    fn test_unzip_hint() {
        let hint = hint_unzip(&cmd("unzip", &["file.zip"]));
        assert_eq!(hint.modern_command, "ouch");
        assert!(hint.hint.contains("ouch decompress"));
    }

    #[test]
    fn test_zip_create_hint() {
        let hint = hint_zip(&cmd("zip", &["out.zip", "a.txt", "b.txt"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("ouch compress"));
    }

    #[test]
    fn test_zip_version_no_hint() {
        let hint = hint_zip(&cmd("zip", &["--version"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_tar_extract_dash_hint() {
        let hint = hint_tar(&cmd("tar", &["-xzf", "archive.tar.gz"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("ouch decompress"));
    }

    #[test]
    fn test_tar_extract_long_hint() {
        let hint = hint_tar(&cmd("tar", &["--extract", "-f", "archive.tar"]));
        assert!(hint.is_some());
    }

    #[test]
    fn test_tar_extract_bsd_bundle_hint() {
        // BSD-style: no leading dash
        let hint = hint_tar(&cmd("tar", &["xzf", "archive.tar.gz"]));
        assert!(hint.is_some());
    }

    #[test]
    fn test_tar_create_no_hint() {
        // tar -czf is fine, streaming/create has no clean ouch replacement
        let hint = hint_tar(&cmd("tar", &["-czf", "out.tar.gz", "dir"]));
        assert!(hint.is_none());
    }

    #[test]
    fn test_tar_help_no_hint() {
        let hint = hint_tar(&cmd("tar", &["--version"]));
        assert!(hint.is_none());
    }
}

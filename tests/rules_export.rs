//! Integration tests for the gate-docs generator.
//!
//! These run the public `tool_gates::rules_export::export_markdown` entry point
//! against the repo's real `rules/*.toml` (resolved from `CARGO_MANIFEST_DIR`)
//! and assert the emitted markdown matches the design component shapes and is
//! byte-identical on re-run.

use std::fs;
use std::path::{Path, PathBuf};

use tool_gates::rules_export::{build_slug, export_markdown, reason_to_html, row_id};

/// Absolute path to the repo's `rules/` directory, independent of the test
/// runner's working directory.
fn rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules")
}

/// Create a unique temp output dir under the system temp root. Avoids pulling
/// in a tempfile dependency; the process id plus a label keeps parallel test
/// runs from colliding.
fn temp_out(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tg-docs-test-{}-{}-{}",
        label,
        std::process::id(),
        // nanosecond clock disambiguates two dirs requested in the same test
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn read_gate(out: &Path, gate: &str) -> String {
    fs::read_to_string(out.join("gates").join(format!("{gate}.md"))).unwrap()
}

fn read_hints(out: &Path) -> String {
    fs::read_to_string(out.join("hints.md")).unwrap()
}

#[test]
fn exports_all_gate_pages_and_floor() {
    let out = temp_out("all");
    export_markdown(&rules_dir(), &out).unwrap();

    for gate in [
        "basics",
        "beads",
        "cloud",
        "devtools",
        "filesystem",
        "gh",
        "git",
        "network",
        "package_managers",
        "runtimes",
        "shortcut",
        "system",
        "tool_gates",
    ] {
        let path = out.join("gates").join(format!("{gate}.md"));
        assert!(path.exists(), "missing gate page: {}", path.display());
    }
    assert!(out.join("security-floor.md").exists());
    assert!(out.join("hints.md").exists());

    fs::remove_dir_all(&out).ok();
}

#[test]
fn output_is_byte_identical_on_rerun() {
    let a = temp_out("idem-a");
    let b = temp_out("idem-b");
    export_markdown(&rules_dir(), &a).unwrap();
    export_markdown(&rules_dir(), &b).unwrap();

    // Compare every generated file byte-for-byte.
    let mut files: Vec<String> = vec!["security-floor.md".to_string(), "hints.md".to_string()];
    for entry in fs::read_dir(a.join("gates")).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        files.push(format!("gates/{name}"));
    }
    files.sort();

    for rel in &files {
        let fa = fs::read(a.join(rel)).unwrap();
        let fb = fs::read(b.join(rel)).unwrap();
        assert_eq!(fa, fb, "non-deterministic output for {rel}");
    }

    // Re-export into the same dir a third time and confirm git's content is
    // unchanged (overwrite is idempotent, not append).
    let git_first = read_gate(&a, "git");
    export_markdown(&rules_dir(), &a).unwrap();
    let git_second = read_gate(&a, "git");
    assert_eq!(git_first, git_second);

    fs::remove_dir_all(&a).ok();
    fs::remove_dir_all(&b).ok();
}

#[test]
fn git_page_has_expected_shapes() {
    let out = temp_out("git");
    export_markdown(&rules_dir(), &out).unwrap();
    let git = read_gate(&out, "git");

    // gate-head + breadcrumb + h1
    assert!(git.contains("<div class=\"gate-head\">"));
    assert!(git.contains("<h1>Git gate</h1>"));
    assert!(git.contains("<span class=\"tag\">priority <b>10</b></span>"));

    // chips row with a real total count
    assert!(git.contains("<div class=\"chips\""));

    // a known allow row with the deduped id (not "git-git-status")
    assert!(git.contains("id=\"git-status\""));
    assert!(!git.contains("id=\"git-git-status\""));

    // both allow and ask pills appear on the page
    assert!(git.contains("<span class=\"pill allow\">"));
    assert!(git.contains("<span class=\"pill ask\">"));

    // github blob source link for the gate TOML
    assert!(git.contains("https://github.com/camjac251/tool-gates/blob/main/rules/git.toml"));
    assert!(git.contains("<span class=\"count\">"));
    assert!(git.contains(" patterns</span>"));

    // a warn rule carries the warn-tag
    assert!(git.contains("<span class=\"warn-tag\""));

    fs::remove_dir_all(&out).ok();
}

#[test]
fn filesystem_page_is_block_first_and_multi_program() {
    let out = temp_out("fs");
    export_markdown(&rules_dir(), &out).unwrap();
    let fs_page = read_gate(&out, "filesystem");

    // The Blocked card must appear before the Allowed and Asks cards. The
    // filesystem gate carries [meta].card_titles suffixes ("destructive
    // paths" / "read-only" / "mutations").
    let blocked = fs_page
        .find("<h2>Blocked \u{b7} destructive paths</h2>")
        .expect("Blocked card with descriptive suffix");
    let allowed = fs_page
        .find("<h2>Allowed \u{b7} read-only</h2>")
        .expect("Allowed card with descriptive suffix");
    let asks = fs_page
        .find("<h2>Asks first \u{b7} mutations</h2>")
        .expect("Asks card with descriptive suffix");
    assert!(blocked < allowed, "Blocked card must come before Allowed");
    assert!(allowed < asks, "Allowed card must come before Asks");

    // A concrete block rule-row (the rm catastrophic-path floor).
    assert!(fs_page.contains("data-decision=\"block\""));
    assert!(fs_page.contains("id=\"filesystem-rm-rf\""));
    assert!(fs_page.contains("<span class=\"pill block\">"));

    // Multi-program: rm and a distinct program (mv) both render.
    assert!(fs_page.contains("<span class=\"prog\">rm</span>"));
    assert!(fs_page.contains("<span class=\"prog\">mv</span>"));

    fs::remove_dir_all(&out).ok();
}

#[test]
fn security_floor_aggregates_warn_and_block_rules() {
    let out = temp_out("floor");
    export_markdown(&rules_dir(), &out).unwrap();
    let floor = fs::read_to_string(out.join("security-floor.md")).unwrap();

    // Two cards.
    assert!(floor.contains("<h2>Hard blocks \u{b7} denied without prompting</h2>"));
    assert!(floor.contains("<h2>Warn rules \u{b7} dangerous but recoverable</h2>"));

    // Every floor row prepends a .rule-gate span naming the source gate.
    assert!(floor.contains("<span class=\"rule-gate\">git</span>"));
    assert!(floor.contains("<span class=\"rule-gate\">filesystem</span>"));

    // Warn rows from the git gate: push --force, reset --hard, clean. Each is
    // an ask row with the warn-tag.
    assert!(
        floor.contains("<span class=\"prog\">git</span> push <span class=\"flag\">--force</span>")
    );
    assert!(
        floor.contains("<span class=\"prog\">git</span> reset <span class=\"flag\">--hard</span>")
    );
    assert!(floor.contains("<span class=\"prog\">git</span> clean"));
    assert!(floor.contains("<span class=\"warn-tag\""));

    // A known hard block: rm -rf root, denied without prompting.
    assert!(floor.contains("id=\"filesystem-rm-rf\""));
    assert!(floor.contains("data-decision=\"block\""));

    fs::remove_dir_all(&out).ok();
}

#[test]
fn slug_helper_is_deterministic_and_dedupes_gate() {
    // program + subcommand + flag, kebab-cased
    assert_eq!(build_slug("git", &["status"]), "git-status");
    assert_eq!(build_slug("git", &["push", "--force"]), "git-push-force");
    assert_eq!(
        build_slug("filesystem", &["rm", "-rf /"]),
        "filesystem-rm-rf"
    );

    // row_id dedupes a redundant leading gate token (single-program gates) and
    // prepends the gate otherwise (multi-program gates).
    assert_eq!(row_id("git", "git-status"), "git-status");
    assert_eq!(row_id("filesystem", "rm-rf"), "filesystem-rm-rf");

    // collision case: callers disambiguate equal ids with a numeric suffix.
    // build_slug itself is collision-agnostic; two identical inputs produce the
    // same slug, which finalize_ids (covered by lib unit tests) then suffixes.
    assert_eq!(
        build_slug("git", &["tag"]),
        build_slug("git", &["tag"]),
        "same input must yield the same slug"
    );
}

#[test]
fn reason_html_converts_backtick_spans() {
    assert_eq!(
        reason_to_html("Safer: `git stash` first."),
        "Safer: <code>git stash</code> first."
    );
    // markup chars inside a code span are escaped
    assert_eq!(
        reason_to_html("Removes `<file>`."),
        "Removes <code>&lt;file&gt;</code>."
    );
}

/// Extract the `.rule-reason` text (if any) for a given `id="..."` rule-row in a
/// generated page. Returns `None` when the row has no reason div.
fn reason_for_row(page: &str, row_id: &str) -> Option<String> {
    let anchor = format!("id=\"{row_id}\"");
    let row_start = page.find(&anchor)?;
    // Bound the search to this row's div by stopping at the next rule-row.
    let rest = &page[row_start..];
    let row_end = rest[1..]
        .find("<div class=\"rule-row\"")
        .map(|i| i + 1)
        .unwrap_or(rest.len());
    let row = &rest[..row_end];
    let needle = "<div class=\"rule-reason\">";
    let start = row.find(needle)? + needle.len();
    let end = row[start..].find("</div>")? + start;
    Some(row[start..end].to_string())
}

#[test]
fn basics_renders_categorized_command_grid() {
    let out = temp_out("basics-grid");
    export_markdown(&rules_dir(), &out).unwrap();
    let basics = read_gate(&out, "basics");

    // basics renders a categorized command-chip grid, not decision rule-rows.
    assert!(
        basics.contains("<div class=\"cmd-grid\">"),
        "basics should render a command grid"
    );
    assert!(
        basics.contains("<div class=\"cat\">"),
        "grid should have category blocks"
    );
    assert!(
        basics.contains("<h4>Display &amp; output</h4>"),
        "first category heading renders (HTML-escaped &)"
    );
    assert!(
        basics.contains("<div class=\"chips-line\">"),
        "categories list commands as chips"
    );
    assert!(
        basics.contains("<span>cat</span>") && basics.contains("<span>rg</span>"),
        "known commands render as chips"
    );

    // A grid page has no decision rule-rows and omits the seg-bar + filter chips.
    assert!(
        !basics.contains("class=\"rule-row\""),
        "basics must not render decision rule-rows"
    );
    assert!(
        !basics.contains("class=\"seg-bar\""),
        "basics must not render a decision seg-bar"
    );
    assert!(
        !basics.contains("class=\"chips\""),
        "basics must not render the decision filter chips"
    );

    fs::remove_dir_all(&out).ok();
}

#[test]
fn catch_all_allow_rows_render_their_reason() {
    let out = temp_out("catch-all");
    export_markdown(&rules_dir(), &out).unwrap();
    let devtools = read_gate(&out, "devtools");

    // pytest is `unknown_action = "allow"` with no explicit allow/ask/block
    // rule, so the generator synthesizes an "(all subcommands)" allow row. It
    // now carries the program's catch-all `reason` instead of rendering bare.
    let pytest_reason = reason_for_row(&devtools, "devtools-pytest")
        .expect("pytest catch-all row should have a reason");
    assert!(
        pytest_reason.contains("Runs the Python test suite"),
        "pytest catch-all row should show its reason, got: {pytest_reason}"
    );

    fs::remove_dir_all(&out).ok();
}

#[test]
fn hints_page_renders_catalog() {
    let out = temp_out("hints-page");
    export_markdown(&rules_dir(), &out).unwrap();
    let hints = read_hints(&out);

    // Reference-page header shape.
    assert!(hints.contains("<h1 id=\"hints-h1\">Modern CLI hints</h1>"));
    assert!(hints.contains("<p class=\"breadcrumb\">"));
    assert!(hints.contains("<p class=\"page-lede\">"));

    // Design hint-panel classes so the ported CSS applies.
    assert!(hints.contains("<div class=\"hints\">"));
    assert!(hints.contains("<div class=\"hint-row\">"));
    assert!(hints.contains("<div class=\"arrow\">"));
    assert!(hints.contains("<div class=\"why\">"));

    // A few representative catalog pairings render.
    assert!(hints.contains("<s>cat</s>"));
    assert!(hints.contains("<s>find</s>"));
    assert!(hints.contains("<s>grep</s>"));

    // Catalog text is HTML-escaped (the head/tail entries contain <file>).
    assert!(hints.contains("&lt;file&gt;"));
    assert!(!hints.contains("<file>"));

    fs::remove_dir_all(&out).ok();
}

#[test]
fn gate_lede_renders_when_meta_lede_set() {
    let out = temp_out("lede");
    export_markdown(&rules_dir(), &out).unwrap();

    // git carries an editorial [meta].lede paragraph.
    let git = read_gate(&out, "git");
    let lede_idx = git
        .find("<p class=\"gate-lede\">Read-only history and inspection")
        .expect("git gate-lede paragraph rendered");
    // Lede sits inside the gate-head block, after the summary, before the chips
    // filter strip.
    let summary_idx = git.find("class=\"summary\"").expect("summary block");
    let chips_idx = git.find("class=\"chips\"").expect("chips block");
    assert!(summary_idx < lede_idx, "lede follows summary");
    assert!(lede_idx < chips_idx, "lede precedes chips");
}

#[test]
fn closing_note_renders_when_meta_note_set_with_alert_svg() {
    let out = temp_out("note");
    export_markdown(&rules_dir(), &out).unwrap();

    // git carries an editorial [meta].note that closes the page.
    let git = read_gate(&out, "git");
    let note_idx = git
        .find("<p class=\"note\">")
        .expect("note callout rendered");
    // The amber alert SVG wraps the prose.
    assert!(
        git[note_idx..].contains("<svg class=\"alert\""),
        "alert SVG present in note callout"
    );
    assert!(git.contains("<b>Hard blocks live in other gates.</b>"));

    // Beads has no closing note in the design; verify the generator
    // honours that by not emitting one.
    let beads = read_gate(&out, "beads");
    assert!(
        !beads.contains("<p class=\"note\">"),
        "beads should not have a closing note"
    );
}

#[test]
fn descriptive_card_titles_use_card_titles_meta() {
    let out = temp_out("titles");
    export_markdown(&rules_dir(), &out).unwrap();

    // filesystem carries all three card_titles.
    let fs_page = read_gate(&out, "filesystem");
    assert!(fs_page.contains("<h2>Blocked \u{b7} destructive paths</h2>"));
    assert!(fs_page.contains("<h2>Allowed \u{b7} read-only</h2>"));
    assert!(fs_page.contains("<h2>Asks first \u{b7} mutations</h2>"));

    // cloud has block rules but no card_titles.block (matches the design).
    // The bare "Blocked" header still renders.
    let cloud = read_gate(&out, "cloud");
    assert!(
        cloud.contains("<h2>Blocked</h2>"),
        "cloud falls back to bare Blocked title when card_titles.block is unset"
    );
    assert!(cloud.contains("<h2>Allowed \u{b7} inspection</h2>"));
    assert!(cloud.contains("<h2>Asks first \u{b7} mutations</h2>"));
}

#[test]
fn behavior_tags_replace_custom_handler_auto_tags_when_populated() {
    let out = temp_out("tags");
    export_markdown(&rules_dir(), &out).unwrap();

    // git declares behavior_tags; the generator must use those and must NOT
    // leak internal handler-function names like `check_git_add`.
    let git = read_gate(&out, "git");
    assert!(git.contains("<b>--dry-run</b> / <b>-n</b> always allows"));
    assert!(git.contains("aliases resolved from <b>~/.gitconfig</b>"));
    assert!(
        !git.contains("custom handler <b>check_git_add</b>"),
        "behavior_tags should suppress the legacy custom-handler auto-tags"
    );
    assert!(
        !git.contains("custom handler <b>extract_subcommand</b>"),
        "behavior_tags should suppress the legacy custom-handler auto-tags"
    );
}

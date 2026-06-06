//! Generate the mdBook gate documentation from `rules/*.toml`.
//!
//! `tool-gates rules export --format md` walks every `rules/<gate>.toml`, parses
//! it through [`crate::rules_schema`], and emits one `<out>/gates/<gate>.md` per
//! gate plus the cross-cut `<out>/security-floor.md` and the `<out>/hints.md`
//! modern-CLI reference. The emitted HTML shapes are fixed by what the theme
//! CSS in `docs/theme/` targets, so the markup here applies unchanged.
//!
//! Output is byte-identical on re-run: gates sort by name, programs within a
//! gate sort by name, rules within a bucket keep their TOML order, and buckets
//! render Block, Allow, Ask. Slugs are deterministic with a numeric-suffix
//! tiebreak for collisions.

use std::fs;
use std::io;
use std::path::Path;

use crate::hints::{HintCatalogEntry, hint_catalog, program_hint};
use crate::rules_schema::{AllowRule, AskRule, BlockRule, ProgramRules, RuleFile, UnknownAction};

/// GitHub blob base for `.src` source links. The design links every gate
/// card to its TOML on `main`.
const SRC_REPO_BLOB: &str = "https://github.com/camjac251/tool-gates/blob/main/rules";

/// GitHub tree URL for the aggregated security-floor source links.
const SRC_REPO_TREE: &str = "https://github.com/camjac251/tool-gates/tree/main/rules";

/// The decision a rendered rule row carries. Distinct from the runtime
/// `Decision` enum because the docs only ever show these three pills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowDecision {
    Allow,
    Ask,
    Block,
}

impl RowDecision {
    /// The `data-decision` attribute / pill modifier class.
    fn class(self) -> &'static str {
        match self {
            RowDecision::Allow => "allow",
            RowDecision::Ask => "ask",
            RowDecision::Block => "block",
        }
    }

    /// The uppercased label inside the pill.
    fn label(self) -> &'static str {
        match self {
            RowDecision::Allow => "Allow",
            RowDecision::Ask => "Ask",
            RowDecision::Block => "Block",
        }
    }
}

/// One rendered rule row, derived from a single TOML rule (or a synthesized
/// catch-all for `unknown_action` programs). Fields are pre-rendered HTML
/// fragments so the row template is a straight join.
#[derive(Debug, Clone)]
pub struct RuleEntry {
    /// Program name (e.g. `git`). Used for the `.prog` span and slug.
    pub program: String,
    /// Inner HTML of `.rule-cmd` after the program: subcommand text plus any
    /// `.flag` spans. Empty when the row is just the bare program.
    pub cmd_rest_html: String,
    pub decision: RowDecision,
    pub warn: bool,
    /// The TOML reason, with backtick spans converted to `<code>`. Empty for
    /// allow rows that have no reason.
    pub reason_html: String,
    /// Slug suffix (program + subcommand + flag, kebab-cased). Stable per rule.
    /// The row `id` is derived from this plus the gate name by
    /// [`finalize_ids`], which dedupes a redundant leading gate token so a
    /// single-program gate like `git` yields `git-status`, not `git-git-status`.
    pub slug: String,
    /// Final per-page HTML id, set by [`finalize_ids`]. Unique within the page.
    pub id: String,
}

/// Per-gate parse + render unit.
struct Gate {
    stem: String,
    name: String,
    priority: u32,
    rule_file: RuleFile,
}

/// Walk `rules_dir`, render every gate page into `out_dir/gates/` and the
/// security floor into `out_dir/security-floor.md`.
pub fn export_markdown(rules_dir: &Path, out_dir: &Path) -> io::Result<()> {
    let gates = load_gates(rules_dir)?;

    let gates_dir = out_dir.join("gates");
    fs::create_dir_all(&gates_dir)?;

    for gate in &gates {
        let page = render_gate_page(gate);
        fs::write(gates_dir.join(format!("{}.md", gate.stem)), page)?;
    }

    let floor = render_security_floor(&gates);
    fs::write(out_dir.join("security-floor.md"), floor)?;

    let hints = render_hints_page();
    fs::write(out_dir.join("hints.md"), hints)?;

    Ok(())
}

/// Read and parse every `*.toml` under `rules_dir` into [`Gate`], sorted by
/// gate name for deterministic output. The gate name is the file stem so a
/// missing `[meta].name` still produces a stable filename.
fn load_gates(rules_dir: &Path) -> io::Result<Vec<Gate>> {
    let mut paths: Vec<_> = fs::read_dir(rules_dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("toml"))
        .collect();
    paths.sort();

    let mut gates = Vec::with_capacity(paths.len());
    for path in paths {
        let content = fs::read_to_string(&path)?;
        let rule_file: RuleFile = toml::from_str(&content).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse {}: {e}", path.display()),
            )
        })?;
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        let name = rule_file.meta.name.clone().unwrap_or_else(|| stem.clone());
        let priority = rule_file.meta.priority.unwrap_or(0);
        gates.push(Gate {
            stem,
            name,
            priority,
            rule_file,
        });
    }
    gates.sort_by(|a, b| a.stem.cmp(&b.stem));
    Ok(gates)
}

/// Bucket counts for the seg-bar and chips.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub allow: usize,
    pub ask: usize,
    pub block: usize,
}

impl Counts {
    fn total(&self) -> usize {
        self.allow + self.ask + self.block
    }
}

/// Compute the bucket counts for a gate from its rendered rows. Driving counts
/// off the rendered rows (not raw TOML) keeps the seg-bar, chips, and per-card
/// `{n} patterns` totals consistent with what actually renders.
pub fn compute_counts(rows: &[RuleEntry]) -> Counts {
    let mut c = Counts::default();
    for row in rows {
        match row.decision {
            RowDecision::Allow => c.allow += 1,
            RowDecision::Ask => c.ask += 1,
            RowDecision::Block => c.block += 1,
        }
    }
    c
}

/// Convert a TOML `reason` string into HTML, turning backtick-quoted spans into
/// `<code>...</code>` and HTML-escaping everything else. Non-code text is
/// escaped first so reasons can never inject markup; code spans are escaped too
/// (a backtick span like `` `<file>` `` must render as literal `<file>`).
pub fn reason_to_html(reason: &str) -> String {
    let mut out = String::with_capacity(reason.len() + 16);
    let mut in_code = false;
    let mut segment = String::new();
    for ch in reason.chars() {
        if ch == '`' {
            if in_code {
                out.push_str("<code>");
                out.push_str(&html_escape(&segment));
                out.push_str("</code>");
            } else {
                out.push_str(&html_escape(&segment));
            }
            segment.clear();
            in_code = !in_code;
        } else {
            segment.push(ch);
        }
    }
    // Trailing segment. An unbalanced backtick (odd count) leaves `in_code`
    // true; treat the dangling tail as plain text rather than emitting an
    // unclosed <code>, so the output is always valid HTML.
    out.push_str(&html_escape(&segment));
    out
}

/// Minimal HTML escaping for text nodes and attribute-free content.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Kebab-case a single token: lowercase, runs of non-alphanumeric collapse to a
/// single hyphen, leading/trailing hyphens trimmed. `--force` -> `force`,
/// `-rf /` -> `rf`, `config set` -> `config-set`.
fn kebab(token: &str) -> String {
    let mut out = String::with_capacity(token.len());
    let mut prev_hyphen = true; // trims leading hyphens
    for ch in token.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_hyphen = false;
        } else if !prev_hyphen {
            out.push('-');
            prev_hyphen = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

/// Build the base slug suffix from program + subcommand + flag fragments.
/// Deterministic. Empty fragments are skipped. Collisions within a gate are
/// resolved later by [`disambiguate_slugs`].
pub fn build_slug(program: &str, parts: &[&str]) -> String {
    let mut pieces: Vec<String> = Vec::new();
    let p = kebab(program);
    if !p.is_empty() {
        pieces.push(p);
    }
    for part in parts {
        let k = kebab(part);
        if !k.is_empty() {
            pieces.push(k);
        }
    }
    if pieces.is_empty() {
        "rule".to_string()
    } else {
        pieces.join("-")
    }
}

/// Compose the HTML id for a row from the gate name and the rule slug. The slug
/// starts with the program name; when the program equals the gate (single-
/// program gates like `git`, `gh`), the gate prefix is already present in the
/// slug, so the id is the slug itself (`git-status`). Otherwise the gate is
/// prepended (`filesystem-rm-rf`, `cloud-aws-iam-delete-user`).
pub fn row_id(gate: &str, slug: &str) -> String {
    if slug == gate || slug.starts_with(&format!("{gate}-")) {
        slug.to_string()
    } else {
        format!("{gate}-{slug}")
    }
}

/// Compute each row's final HTML id from the gate name, then ensure uniqueness
/// within the page by appending `-2`, `-3`, ... to later collisions. Order-
/// stable: the first occurrence keeps the bare id. HTML ids must be unique, so
/// disambiguation runs on the composed id, not the raw slug.
fn finalize_ids(gate: &str, rows: &mut [RuleEntry]) {
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for row in rows.iter_mut() {
        let base = row_id(gate, &row.slug);
        let count = seen.entry(base.clone()).or_insert(0);
        *count += 1;
        row.id = if *count > 1 {
            format!("{base}-{count}")
        } else {
            base
        };
    }
}

/// Render the `.rule-cmd` inner-after-program HTML for a subcommand + optional
/// flags. The program `.prog` span is emitted by the row template; this returns
/// the trailing text. Multi-word subcommands render as plain text; flags render
/// as `.flag` spans.
fn cmd_rest(subcommand_parts: &[&str], flags: &[String]) -> String {
    let mut out = String::new();
    if !subcommand_parts.is_empty() {
        out.push(' ');
        out.push_str(&html_escape(&subcommand_parts.join(" ")));
    }
    for flag in flags {
        out.push_str(" <span class=\"flag\">");
        out.push_str(&html_escape(flag));
        out.push_str("</span>");
    }
    out
}

fn rows_for_program(program: &ProgramRules) -> Vec<RuleEntry> {
    let mut rows = Vec::new();

    for block in &program.block {
        rows.push(block_row(program, block));
    }
    for allow in &program.allow {
        rows.push(allow_row(program, allow));
    }
    // Synthesize a catch-all allow when the program defaults to allow and has
    // no explicit allow rule to represent it. The reason is the program's
    // docs-only `[meta]`-style `reason` field when set, else a program-level
    // modern-CLI hint, else empty.
    if program.unknown_action == UnknownAction::Allow
        && program.allow.is_empty()
        && program.ask.is_empty()
        && program.block.is_empty()
    {
        let reason_html = match program.reason.as_deref() {
            Some(r) if !r.trim().is_empty() => reason_to_html(r),
            _ => allow_reason_html(&program.name, None),
        };
        rows.push(RuleEntry {
            program: program.name.clone(),
            cmd_rest_html: " <span class=\"sub-note\">(all subcommands)</span>".to_string(),
            decision: RowDecision::Allow,
            warn: false,
            reason_html,
            slug: build_slug(&program.name, &[]),
            id: String::new(),
        });
    }
    for ask in &program.ask {
        rows.push(ask_row(program, ask));
    }

    rows
}

fn block_row(program: &ProgramRules, block: &BlockRule) -> RuleEntry {
    let parts = owned_parts(
        &block.subcommand_parts(),
        block.subcommand_prefix.as_deref(),
        None,
    );
    let part_refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    // if_args_contain values render as .flag spans (e.g. the rm catch-all's
    // `/`, `~/`); trim whitespace the TOML uses for word-boundary matching.
    let flags: Vec<String> = block
        .if_args_contain
        .iter()
        .map(|s| s.trim().to_string())
        .collect();
    let mut slug_parts: Vec<&str> = part_refs.clone();
    for f in &flags {
        slug_parts.push(f);
    }
    RuleEntry {
        program: program.name.clone(),
        cmd_rest_html: cmd_rest(&part_refs, &flags),
        decision: RowDecision::Block,
        warn: false,
        reason_html: reason_to_html(&block.reason),
        slug: build_slug(&program.name, &slug_parts),
        id: String::new(),
    }
}

/// Build the owned subcommand-part list for a rule: the `subcommand` /
/// `subcommands` words, then `subcommand_prefix`, then `action_prefix` rendered
/// as `<action>-*` (matching the design's `aws organizations delete-*`).
/// Owned so the action string has no borrow-lifetime constraints.
fn owned_parts(
    subcommand_parts: &[&str],
    subcommand_prefix: Option<&str>,
    action_prefix: Option<&str>,
) -> Vec<String> {
    let mut parts: Vec<String> = subcommand_parts.iter().map(|s| s.to_string()).collect();
    if let Some(prefix) = subcommand_prefix {
        parts.push(prefix.to_string());
    }
    if let Some(action) = action_prefix {
        parts.push(format!("{action}-*"));
    }
    parts
}

/// Reason HTML for an allow row.
///
/// A TOML `reason` always wins. When the allow rule has no reason and the bare
/// program maps to an unconditional modern-CLI hint (see [`program_hint`]), the
/// hint is surfaced as the row reason so the docs teach the better tool without
/// blocking. Allow rows with neither a TOML reason nor a program-level hint stay
/// bare, matching the runtime's allow-then-teach philosophy.
fn allow_reason_html(program: &str, toml_reason: Option<&str>) -> String {
    if let Some(reason) = toml_reason {
        return reason_to_html(reason);
    }
    program_hint(program)
        .map(hint_reason_html)
        .unwrap_or_default()
}

/// Render a program-level hint as an allow-row reason, e.g.
/// `Allowed. Modern alternative: <code>bat</code> (...why...).` The modern
/// command renders in a `<code>` span; the why clause is escaped as plain text.
fn hint_reason_html(entry: &HintCatalogEntry) -> String {
    format!(
        "Allowed. Modern alternative: <code>{}</code> ({})",
        html_escape(entry.modern),
        html_escape(entry.why),
    )
}

fn allow_row(program: &ProgramRules, allow: &AllowRule) -> RuleEntry {
    let parts = owned_parts(
        &allow.subcommand_parts(),
        allow.subcommand_prefix.as_deref(),
        allow.action_prefix.as_deref(),
    );
    let part_refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    let mut slug_parts: Vec<&str> = part_refs.clone();
    for f in &allow.if_flags_any {
        slug_parts.push(f);
    }
    RuleEntry {
        program: program.name.clone(),
        cmd_rest_html: cmd_rest(&part_refs, &allow.if_flags_any),
        decision: RowDecision::Allow,
        warn: false,
        reason_html: allow_reason_html(&program.name, allow.reason.as_deref()),
        slug: build_slug(&program.name, &slug_parts),
        id: String::new(),
    }
}

fn ask_row(program: &ProgramRules, ask: &AskRule) -> RuleEntry {
    let parts = owned_parts(
        &ask.subcommand_parts(),
        ask.subcommand_prefix.as_deref(),
        ask.action_prefix.as_deref(),
    );
    let part_refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    // Prefer if_flags_any (the common form); fall back to if_flags.
    let flags: Vec<String> = if !ask.if_flags_any.is_empty() {
        ask.if_flags_any.clone()
    } else {
        ask.if_flags.clone()
    };
    let mut slug_parts: Vec<&str> = part_refs.clone();
    for f in &flags {
        slug_parts.push(f);
    }
    RuleEntry {
        program: program.name.clone(),
        cmd_rest_html: cmd_rest(&part_refs, &flags),
        decision: RowDecision::Ask,
        warn: ask.warn,
        reason_html: reason_to_html(&ask.reason),
        slug: build_slug(&program.name, &slug_parts),
        id: String::new(),
    }
}

/// All rendered rows for a gate: every program (sorted by name), each program's
/// rows in bucket order, plus `safe_commands` (basics) as allow rows and
/// `conditional_allow` entries as ask rows. Slugs are disambiguated across the
/// whole gate.
fn gate_rows(gate: &Gate) -> Vec<RuleEntry> {
    let mut rows = Vec::new();

    let mut programs: Vec<&ProgramRules> = gate.rule_file.programs.iter().collect();
    programs.sort_by(|a, b| a.name.cmp(&b.name));
    for program in programs {
        rows.extend(rows_for_program(program));
    }

    // safe_commands (basics): each is an always-allow program with no rules.
    // A bare safe command still surfaces a program-level modern-CLI hint when
    // one exists (e.g. `cat` -> bat), matching allow-then-teach.
    for cmd in &gate.rule_file.safe_commands {
        rows.push(RuleEntry {
            program: cmd.clone(),
            cmd_rest_html: String::new(),
            decision: RowDecision::Allow,
            warn: false,
            reason_html: allow_reason_html(cmd, None),
            slug: build_slug(cmd, &[]),
            id: String::new(),
        });
    }

    // conditional_allow (e.g. sed -i): safe without the flag, otherwise the
    // configured on_flag action. Render the on-flag decision as the row.
    for cond in &gate.rule_file.conditional_allow {
        let decision = match cond.on_flag_present {
            crate::rules_schema::OnFlagAction::Block => RowDecision::Block,
            crate::rules_schema::OnFlagAction::Ask => RowDecision::Ask,
            crate::rules_schema::OnFlagAction::Skip => RowDecision::Allow,
        };
        let flags: Vec<String> = cond.unless_flags.clone();
        let reason_html = cond
            .description
            .as_deref()
            .map(reason_to_html)
            .unwrap_or_default();
        let mut slug_parts: Vec<&str> = Vec::new();
        for f in &cond.unless_flags {
            slug_parts.push(f);
        }
        rows.push(RuleEntry {
            program: cond.program.clone(),
            cmd_rest_html: cmd_rest(&[], &flags),
            decision,
            warn: false,
            reason_html,
            slug: build_slug(&cond.program, &slug_parts),
            id: String::new(),
        });
    }

    finalize_ids(&gate.stem, &mut rows);
    rows
}

/// The github source-link SVG (file icon) used in every rule-card header.
fn src_link(href: &str, label: &str) -> String {
    format!(
        "<a href=\"{href}\" class=\"src\" target=\"_blank\" rel=\"noopener\">\n      <svg width=\"11\" height=\"11\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z\"></path><polyline points=\"14 2 14 8 20 8\"></polyline></svg>\n      {label}\n    </a>"
    )
}

/// The decision pill SVG body (paths only). The theme CSS expects this exact
/// geometry: 12x12 viewBox 24, stroke-width 2.4, round caps. Allow adds round
/// joins.
fn pill_svg(decision: RowDecision) -> &'static str {
    match decision {
        RowDecision::Allow => {
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.4\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><polyline points=\"20 6 9 17 4 12\"></polyline></svg>"
        }
        RowDecision::Ask => {
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.4\" stroke-linecap=\"round\"><line x1=\"9\" y1=\"6\" x2=\"9\" y2=\"18\"></line><line x1=\"15\" y1=\"6\" x2=\"15\" y2=\"18\"></line></svg>"
        }
        RowDecision::Block => {
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.4\" stroke-linecap=\"round\"><line x1=\"6\" y1=\"6\" x2=\"18\" y2=\"18\"></line><line x1=\"18\" y1=\"6\" x2=\"6\" y2=\"18\"></line></svg>"
        }
    }
}

/// Render a `.pill` span for a decision.
fn pill_html(decision: RowDecision) -> String {
    format!(
        "<span class=\"pill {cls}\">{svg}{label}</span>",
        cls = decision.class(),
        svg = pill_svg(decision),
        label = decision.label(),
    )
}

/// Render a single rule-row using its pre-finalized `id`. `gate_prefix` is the
/// source gate name for the optional `.rule-gate` span (used only on the
/// security floor); pass `None` on per-gate pages.
fn render_row(row: &RuleEntry, gate_prefix: Option<&str>) -> String {
    let mut cmd = String::new();
    if let Some(prefix) = gate_prefix {
        cmd.push_str(&format!(
            "<span class=\"rule-gate\">{}</span>",
            html_escape(prefix)
        ));
    }
    cmd.push_str(&format!(
        "<span class=\"prog\">{}</span>",
        html_escape(&row.program)
    ));
    cmd.push_str(&row.cmd_rest_html);

    let warn_tag = if row.warn {
        "<span class=\"warn-tag\" title=\"warn = true in source TOML\">warn</span>"
    } else {
        ""
    };

    let reason = if row.reason_html.is_empty() {
        String::new()
    } else {
        format!("\n  <div class=\"rule-reason\">{}</div>", row.reason_html)
    };

    format!(
        "<div class=\"rule-row\" data-decision=\"{dec}\" id=\"{id}\">\n  <div class=\"rule-cmd\">{cmd}</div>\n  <div>{pill}{warn}</div>{reason}\n</div>",
        dec = row.decision.class(),
        id = row.id,
        cmd = cmd,
        pill = pill_html(row.decision),
        warn = warn_tag,
        reason = reason,
    )
}

/// Render one rule-card (header + rows). `bucket` is the lowercase TOML bucket
/// name used in the `.src` anchor (`#allow`/`#ask`/`#block`).
fn render_card(
    title: &str,
    gate: &str,
    bucket: &str,
    rows: &[&RuleEntry],
    gate_prefix: Option<&str>,
) -> String {
    let src = src_link(
        &format!("{SRC_REPO_BLOB}/{gate}.toml"),
        &format!("rules/{gate}.toml#{bucket}"),
    );
    let mut body = String::new();
    for row in rows {
        body.push('\n');
        body.push_str(&render_row(row, gate_prefix));
    }
    format!(
        "<div class=\"rule-card\">\n  <header>\n    <h2>{title}</h2>\n    {src}\n    <span class=\"count\">{n} patterns</span>\n  </header>\n{body}\n</div>",
        title = title,
        src = src,
        n = rows.len(),
        body = body,
    )
}

fn render_gate_head(gate: &Gate, counts: Option<&Counts>) -> String {
    let mut meta = String::new();
    meta.push_str(&format!(
        "<span class=\"tag\">priority <b>{}</b></span>",
        gate.priority
    ));

    // unknown-action tag: the dominant program's unknown_action, or the gate's
    // first program. Gates here are single-action in practice; use the first
    // program's action, falling back to `ask` (the schema default).
    let unknown_action = gate
        .rule_file
        .programs
        .first()
        .map(|p| p.unknown_action)
        .unwrap_or(UnknownAction::Ask);
    let ua_label = match unknown_action {
        UnknownAction::Ask => "ask",
        UnknownAction::Allow => "allow",
        UnknownAction::Skip => "skip",
        UnknownAction::Block => "block",
    };
    meta.push_str(&format!(
        "\n    <span class=\"tag\">unknown <b>{ua_label}</b></span>"
    ));

    // Behavior tags from [meta].behavior_tags take priority. When empty, fall
    // back to auto-emitting one tag per custom handler, which exposes the
    // internal handler symbol names.
    if !gate.rule_file.meta.behavior_tags.is_empty() {
        for tag in &gate.rule_file.meta.behavior_tags {
            meta.push_str(&format!("\n    <span class=\"tag\">{tag}</span>"));
        }
    } else {
        let mut handlers: Vec<&str> = gate
            .rule_file
            .custom_handlers
            .iter()
            .map(|h| h.handler.as_str())
            .collect();
        handlers.sort_unstable();
        handlers.dedup();
        for handler in handlers {
            meta.push_str(&format!(
                "\n    <span class=\"tag\">custom handler <b>{}</b></span>",
                html_escape(handler)
            ));
        }
    }

    let lede_html = match gate.rule_file.meta.lede.as_deref() {
        Some(lede) if !lede.trim().is_empty() => {
            format!("\n\n  <p class=\"gate-lede\">{lede}</p>")
        }
        _ => String::new(),
    };

    // Summary seg-bar + counts and the filter chips render only for rule-row
    // pages. Grid pages (e.g. basics) pass `None` to omit both: there are no
    // decision buckets to summarize or filter.
    let (summary_html, chips_html) = match counts {
        Some(c) => (
            format!(
                "\n\n  <div class=\"summary\" aria-label=\"Rule counts at a glance\">\n    <div class=\"seg-bar\" role=\"img\" aria-label=\"{na} allow, {nk} ask, {nb} block\">\n      <div class=\"seg allow\" style=\"flex: {na}\"></div>\n      <div class=\"seg ask\"   style=\"flex: {nk}\"></div>\n      <div class=\"seg block\" style=\"flex: {nb}\"></div>\n    </div>\n    <div class=\"counts\">\n      <span class=\"ca\"><i></i><b>{na}</b> allow</span>\n      <span class=\"cas\"><i></i><b>{nk}</b> ask</span>\n      <span class=\"cb\"><i></i><b>{nb}</b> block</span>\n    </div>\n  </div>",
                na = c.allow,
                nk = c.ask,
                nb = c.block,
            ),
            format!(
                "\n\n<div class=\"chips\" role=\"group\" aria-label=\"Filter rules by decision\">\n  <button class=\"chip all\"   data-filter=\"all\"   aria-pressed=\"true\"><i></i>All <span class=\"n\">{nt}</span></button>\n  <button class=\"chip allow\" data-filter=\"allow\" aria-pressed=\"false\"><i></i>Allow <span class=\"n\">{na}</span></button>\n  <button class=\"chip ask\"   data-filter=\"ask\"   aria-pressed=\"false\"><i></i>Ask <span class=\"n\">{nk}</span></button>\n  <button class=\"chip block\" data-filter=\"block\" aria-pressed=\"false\"><i></i>Block <span class=\"n\">{nb}</span></button>\n</div>",
                na = c.allow,
                nk = c.ask,
                nb = c.block,
                nt = c.total(),
            ),
        ),
        None => (String::new(), String::new()),
    };

    format!(
        "<div class=\"gate-head\">\n  <p class=\"breadcrumb\"><a href=\"../index.html\">Gates</a> / {name}</p>\n  <h1>{name} gate</h1>\n  <div class=\"gate-meta\">\n    {meta}\n  </div>{summary}{lede}\n</div>{chips}",
        name = gate.name,
        meta = meta,
        summary = summary_html,
        lede = lede_html,
        chips = chips_html,
    )
}

fn render_gate_page(gate: &Gate) -> String {
    // Grid gates (e.g. basics) declare `command_groups` and render their
    // safe_commands as a categorized chip grid instead of decision rule-rows.
    if !gate.rule_file.command_groups.is_empty() {
        return render_command_grid_page(gate);
    }

    let rows = gate_rows(gate);
    let counts = compute_counts(&rows);

    let blocks: Vec<&RuleEntry> = rows
        .iter()
        .filter(|r| r.decision == RowDecision::Block)
        .collect();
    let allows: Vec<&RuleEntry> = rows
        .iter()
        .filter(|r| r.decision == RowDecision::Allow)
        .collect();
    let asks: Vec<&RuleEntry> = rows
        .iter()
        .filter(|r| r.decision == RowDecision::Ask)
        .collect();

    let mut out = String::new();
    out.push_str(&render_gate_head(gate, Some(&counts)));

    let titles = &gate.rule_file.meta.card_titles;
    let title_block = card_title("Blocked", titles.block.as_deref());
    let title_allow = card_title("Allowed", titles.allow.as_deref());
    let title_ask = card_title("Asks first", titles.ask.as_deref());

    if !blocks.is_empty() {
        out.push_str("\n\n");
        out.push_str(&render_card(
            &title_block,
            &gate.stem,
            "block",
            &blocks,
            None,
        ));
    }
    if !allows.is_empty() {
        out.push_str("\n\n");
        out.push_str(&render_card(
            &title_allow,
            &gate.stem,
            "allow",
            &allows,
            None,
        ));
    }
    if !asks.is_empty() {
        out.push_str("\n\n");
        out.push_str(&render_card(&title_ask, &gate.stem, "ask", &asks, None));
    }

    if let Some(note) = gate.rule_file.meta.note.as_deref() {
        let trimmed = note.trim();
        if !trimmed.is_empty() {
            out.push_str("\n\n");
            out.push_str(&render_gate_note(trimmed));
        }
    }

    out.push('\n');
    out
}

/// Render a command-grid gate page (basics): gate-head with no summary/chips,
/// then a `.cmd-grid` of titled `.cat` blocks listing `safe_commands` as chips,
/// then the optional closing note. Commands render in `command_groups` order;
/// the coverage test guarantees every `safe_command` appears in exactly one
/// group, so nothing is silently dropped.
fn render_command_grid_page(gate: &Gate) -> String {
    let mut out = String::new();
    out.push_str(&render_gate_head(gate, None));

    out.push_str("\n\n<div class=\"cmd-grid\">");
    for group in &gate.rule_file.command_groups {
        let mut chips = String::new();
        for cmd in &group.commands {
            chips.push_str(&format!("<span>{}</span>", html_escape(cmd)));
        }
        out.push_str(&format!(
            "\n  <div class=\"cat\">\n    <h4>{title}</h4>\n    <div class=\"chips-line\">{chips}</div>\n  </div>",
            title = html_escape(&group.title),
            chips = chips,
        ));
    }
    out.push_str("\n</div>");

    if let Some(note) = gate.rule_file.meta.note.as_deref() {
        let trimmed = note.trim();
        if !trimmed.is_empty() {
            out.push_str("\n\n");
            out.push_str(&render_gate_note(trimmed));
        }
    }

    out.push('\n');
    out
}

/// Build a card title with an optional descriptive suffix appended after `·`.
fn card_title(base: &str, suffix: Option<&str>) -> String {
    match suffix {
        Some(s) if !s.trim().is_empty() => format!("{base} · {}", s.trim()),
        _ => base.to_string(),
    }
}

/// Render the amber-alert `.note` callout that closes a gate page when the
/// gate provides one.
fn render_gate_note(note_html: &str) -> String {
    format!(
        "<p class=\"note\">\n  <svg class=\"alert\" width=\"18\" height=\"18\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\"><path d=\"M12 9v4\"></path><path d=\"M12 17h.01\"></path><path d=\"M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z\"></path></svg>\n  <span>{note_html}</span>\n</p>"
    )
}

/// A security-floor row with its source gate attached for the `.rule-gate`
/// label. The floor is a stable, deterministic aggregate across all gates.
struct FloorRow {
    gate: String,
    entry: RuleEntry,
}

/// Aggregate every hard block and every `warn = true` ask across all gates.
///
/// Hard blocks: every `[[programs.block]]` row plus every program whose
/// `unknown_action = block` (those already surface as block rows via
/// [`rows_for_program`], since each such program carries an explicit
/// `[[programs.block]]` in the TOML). Warn rules: every ask row with
/// `warn == true`. Order is by gate name (gates already sorted), then the
/// gate's own row order, so re-runs are byte-identical.
fn collect_floor(gates: &[Gate]) -> (Vec<FloorRow>, Vec<FloorRow>) {
    let mut hard_blocks = Vec::new();
    let mut warn_rules = Vec::new();
    for gate in gates {
        for row in gate_rows(gate) {
            match row.decision {
                RowDecision::Block => hard_blocks.push(FloorRow {
                    gate: gate.stem.clone(),
                    entry: row,
                }),
                RowDecision::Ask if row.warn => warn_rules.push(FloorRow {
                    gate: gate.stem.clone(),
                    entry: row,
                }),
                _ => {}
            }
        }
    }
    (hard_blocks, warn_rules)
}

/// Render one security-floor card. Rows prepend a `.rule-gate` span. The `.src`
/// link points at the aggregated `rules/` tree, not a single gate file.
fn render_floor_card(title: &str, anchor_label: &str, rows: &[FloorRow]) -> String {
    let src = src_link(SRC_REPO_TREE, anchor_label);
    let mut body = String::new();
    for row in rows {
        body.push('\n');
        body.push_str(&render_row(&row.entry, Some(&row.gate)));
    }
    format!(
        "<div class=\"rule-card\">\n  <header>\n    <h2>{title}</h2>\n    {src}\n    <span class=\"count\">{n} patterns</span>\n  </header>\n{body}\n</div>",
        title = title,
        src = src,
        n = rows.len(),
        body = body,
    )
}

/// Render `security-floor.md`: the cross-cut page with Hard blocks and Warn
/// rules cards aggregating every gate.
fn render_security_floor(gates: &[Gate]) -> String {
    let (hard_blocks, warn_rules) = collect_floor(gates);

    let mut out = String::new();
    out.push_str(
        "<p class=\"breadcrumb\"><a href=\"index.html\">Reference</a> / Security floor</p>\n",
    );
    out.push_str("<h1>Security floor</h1>\n");
    out.push_str("<p class=\"page-lede\">Every <code>block</code> rule and every <code>warn = true</code> rule across all 13 gates, on one page. The hard-deny floor fires regardless of <code>settings.json</code>; warn rules ask first but are marked dangerous-but-recoverable. Generated from <code>rules/*.toml</code>; authoritative for security review.</p>\n\n");

    out.push_str(&render_floor_card(
        "Hard blocks \u{b7} denied without prompting",
        "rules/*.toml#block",
        &hard_blocks,
    ));
    out.push_str("\n\n");
    out.push_str(&render_floor_card(
        "Warn rules \u{b7} dangerous but recoverable",
        "warn = true",
        &warn_rules,
    ));
    out.push('\n');
    out
}

/// Render one `.hint-row` for the modern-CLI reference page, mirroring the
/// design's hint panel: a struck-through legacy command, an arrow, the modern
/// replacement, and a why clause. Both command cells carry a `$` prompt `.prog`
/// span. Text is HTML-escaped so catalog content can never inject markup.
fn hint_row(entry: &HintCatalogEntry) -> String {
    format!(
        "<div class=\"hint-row\">\n  <div class=\"old\"><span class=\"prog\">$</span> <s>{legacy}</s></div>\n  <div class=\"arrow\">\u{2192}</div>\n  <div class=\"new\"><span class=\"prog\">$</span> {modern}</div>\n  <div class=\"why\"><b>Tip from tool-gates:</b> {why}</div>\n</div>",
        legacy = html_escape(entry.legacy),
        modern = html_escape(entry.modern),
        why = html_escape(entry.why),
    )
}

/// Render `hints.md`: the "Modern CLI hints" reference page generated from the
/// full [`hint_catalog`]. Hints ride on allow decisions (they never block) and
/// teach a sharper modern tool. Uses the design's `.hints` / `.hint-row`
/// classes so the ported theme CSS applies. Deterministic: the catalog order is
/// fixed, so the page is byte-identical on re-run.
fn render_hints_page() -> String {
    let mut out = String::new();
    out.push_str(
        "<p class=\"breadcrumb\"><a href=\"index.html\">Reference</a> / Modern CLI hints</p>\n",
    );
    out.push_str("<h1 id=\"hints-h1\">Modern CLI hints</h1>\n");
    out.push_str("<p class=\"page-lede\">When a command reaches for a legacy tool that has a sharper modern alternative, tool-gates allows the call <em>and</em> attaches a one-line suggestion via <code>additionalContext</code>. Hints never block; they ride on allow decisions. They fire only when the modern tool is installed on this machine. Generated from the hint catalog in <code>src/hints.rs</code>.</p>\n\n");

    out.push_str("<div class=\"hints\">\n  <header>\n    <h3>Legacy &rarr; modern</h3>\n    <span class=\"note\">7-day cache \u{b7} <code>tool-gates --tools-status</code> to inspect</span>\n  </header>");

    for entry in hint_catalog() {
        out.push('\n');
        out.push_str(&hint_row(entry));
    }

    out.push_str("\n</div>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kebab_basic() {
        assert_eq!(kebab("status"), "status");
        assert_eq!(kebab("config set"), "config-set");
        assert_eq!(kebab("--force"), "force");
        assert_eq!(kebab("-rf /"), "rf");
        assert_eq!(kebab("/*"), "");
        assert_eq!(kebab("delete-*"), "delete");
    }

    #[test]
    fn build_slug_joins_parts() {
        assert_eq!(build_slug("git", &["status"]), "git-status");
        assert_eq!(build_slug("git", &["push", "--force"]), "git-push-force");
        assert_eq!(build_slug("rm", &["-rf /"]), "rm-rf");
        assert_eq!(build_slug("git", &[]), "git");
    }

    /// Build a minimal RuleEntry for slug/id tests.
    fn entry(program: &str, slug: &str) -> RuleEntry {
        RuleEntry {
            program: program.into(),
            cmd_rest_html: String::new(),
            decision: RowDecision::Ask,
            warn: false,
            reason_html: String::new(),
            slug: slug.into(),
            id: String::new(),
        }
    }

    #[test]
    fn row_id_dedupes_gate_prefix() {
        // Single-program gate (program == gate): slug already carries the gate.
        assert_eq!(row_id("git", "git-status"), "git-status");
        assert_eq!(row_id("git", "git"), "git");
        // Multi-program gate (program != gate): prepend the gate.
        assert_eq!(row_id("filesystem", "rm-rf"), "filesystem-rm-rf");
        assert_eq!(
            row_id("cloud", "aws-iam-delete-user"),
            "cloud-aws-iam-delete-user"
        );
    }

    #[test]
    fn finalize_ids_dedupes_and_disambiguates() {
        // git gate, single program: ids drop the duplicate gate token, and
        // collisions (three `git tag` mutation rules) get numeric suffixes.
        let mut rows = vec![
            entry("git", "git-status"),
            entry("git", "git-tag"),
            entry("git", "git-tag"),
            entry("git", "git-tag"),
        ];
        finalize_ids("git", &mut rows);
        assert_eq!(rows[0].id, "git-status");
        assert_eq!(rows[1].id, "git-tag");
        assert_eq!(rows[2].id, "git-tag-2");
        assert_eq!(rows[3].id, "git-tag-3");

        // Multi-program gate: gate prepended, collision suffixed.
        let mut fs_rows = vec![entry("rm", "rm-rf"), entry("rm", "rm-rf")];
        finalize_ids("filesystem", &mut fs_rows);
        assert_eq!(fs_rows[0].id, "filesystem-rm-rf");
        assert_eq!(fs_rows[1].id, "filesystem-rm-rf-2");
    }

    #[test]
    fn reason_code_spans() {
        assert_eq!(
            reason_to_html("Safer: `git stash` first."),
            "Safer: <code>git stash</code> first."
        );
        // backtick span containing markup chars is escaped
        assert_eq!(
            reason_to_html("Matches `<file>` and `<path>`."),
            "Matches <code>&lt;file&gt;</code> and <code>&lt;path&gt;</code>."
        );
        // no backticks: plain escaped text
        assert_eq!(reason_to_html("a & b < c"), "a &amp; b &lt; c");
        // dangling backtick: tail rendered as plain text, valid HTML
        assert_eq!(reason_to_html("trailing `oops"), "trailing oops");
    }

    #[test]
    fn counts_from_rows() {
        let mut allow = entry("a", "a");
        allow.decision = RowDecision::Allow;
        let mut block = entry("b", "b");
        block.decision = RowDecision::Block;
        let ask = entry("c", "c"); // entry() defaults to Ask
        let rows = vec![allow, block, ask];
        let c = compute_counts(&rows);
        assert_eq!(c.allow, 1);
        assert_eq!(c.ask, 1);
        assert_eq!(c.block, 1);
        assert_eq!(c.total(), 3);
    }
}

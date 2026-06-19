//! UI rendering for the review TUI.

use super::app::{
    App, MessageKind, RuleRow, SwitcherRow, View, describe_pattern, extract_operators,
};
use super::theme::{self, Risk};
use crate::pending::display_project_path;
use crate::settings_writer::{RuleType, Scope};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};

const DETAIL_HEIGHT: u16 = 13;

pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),             // Header
            Constraint::Length(1),             // Tab bar
            Constraint::Min(6),                // Active list
            Constraint::Length(DETAIL_HEIGHT), // Detail / decision
            Constraint::Length(1),             // Footer
        ])
        .split(f.area());

    app.layout.commands = chunks[2];
    app.layout.detail = chunks[3];

    draw_header(f, app, chunks[0]);
    draw_tabs(f, app, chunks[1]);

    match app.view {
        View::Pending => {
            draw_pending_list(f, app, chunks[2]);
            draw_decision(f, app, chunks[3]);
        }
        View::Approved | View::Denied => {
            draw_rules_list(f, app, chunks[2]);
            draw_rule_detail(f, app, chunks[3]);
        }
    }

    draw_footer(f, app, chunks[4]);

    if app.show_switcher {
        draw_switcher(f, app, f.area());
    }
}

// === Header + tabs ===

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" tool-gates ", theme::accent_strong()),
        Span::styled("· ", theme::text_muted()),
        Span::styled(app.project_name(), theme::text_strong()),
        Span::styled(
            format!(
                "    {} pending across {} project(s)",
                app.total_pending(),
                app.projects.len()
            ),
            theme::text_muted(),
        ),
    ]));
    f.render_widget(header, area);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let tabs = [
        (View::Pending, "Pending", app.visible.len()),
        (View::Approved, "Approved", app.approved_count),
        (View::Denied, "Denied", app.denied_count),
    ];

    let mut spans = vec![Span::raw(" ")];
    for (i, (view, label, count)) in tabs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("    ", theme::text_muted()));
        }
        let active = app.view == *view;
        let style = if active {
            theme::accent_strong().add_modifier(Modifier::UNDERLINED)
        } else {
            theme::text_muted()
        };
        spans.push(Span::styled(format!("{label} {count}"), style));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

// === Pending list ===

fn draw_pending_list(f: &mut Frame, app: &mut App, area: Rect) {
    let title = if app.is_all_view() {
        " Pending · all projects ".to_string()
    } else {
        format!(" Pending · {} ", app.project_name())
    };
    let block = Block::default()
        .title(panel_title(&title, true))
        .borders(Borders::ALL)
        .border_style(theme::border(false));

    if app.visible.is_empty() {
        let msg = Paragraph::new(
            "\n  Nothing pending here.\n  Press Tab to review the rules you've already approved or denied.",
        )
        .style(theme::text_muted())
        .block(block);
        f.render_widget(msg, area);
        return;
    }

    let is_all = app.is_all_view();
    let cursor = app.command_cursor;
    let items: Vec<ListItem> = app
        .visible
        .iter()
        .enumerate()
        .map(|(i, &entry_idx)| {
            let entry = &app.entries[entry_idx];
            let is_cursor = i == cursor;
            let (prefix, prefix_style) = if is_cursor {
                (" › ", theme::accent_strong())
            } else {
                ("   ", theme::text_muted())
            };

            let mut spans = vec![Span::styled(prefix.to_string(), prefix_style)];
            spans.extend(command_spans(entry));
            spans.push(Span::styled(
                format!("   {}×", entry.count),
                theme::text_muted(),
            ));
            if is_all {
                let proj = display_project_path(entry);
                let short = proj.rsplit('/').next().unwrap_or(&proj).to_string();
                spans.push(Span::styled(format!("   {short}"), theme::text_muted()));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let list = List::new(items).block(block);
    f.render_stateful_widget(list, area, &mut app.command_state);
}

/// Colored spans for a command, each segment prefixed with a decision glyph.
fn command_spans(entry: &crate::pending::PendingApproval) -> Vec<Span<'_>> {
    if entry.breakdown.len() <= 1 {
        let decision = entry
            .breakdown
            .first()
            .map(|p| p.decision.as_str())
            .unwrap_or("ask");
        let color = theme::decision_color(decision);
        return vec![Span::styled(
            format!("{} {}", theme::decision_symbol(decision), entry.command),
            Style::default().fg(color),
        )];
    }

    let operators = extract_operators(&entry.command);
    let mut spans = Vec::new();
    for (i, part) in entry.breakdown.iter().enumerate() {
        if i > 0 {
            let op = operators.get(i - 1).copied().unwrap_or("&&");
            spans.push(Span::styled(format!("  {op}  "), theme::text_muted()));
        }
        let color = theme::decision_color(&part.decision);
        let text = segment_text(part);
        spans.push(Span::styled(
            format!("{} {}", theme::decision_symbol(&part.decision), text),
            Style::default().fg(color),
        ));
    }
    spans
}

fn segment_text(part: &crate::tracking::CommandPart) -> String {
    if part.args.is_empty() {
        part.program.clone()
    } else {
        format!("{} {}", part.program, part.args.join(" "))
    }
}

// === Rules list (Approved / Denied) ===

fn draw_rules_list(f: &mut Frame, app: &mut App, area: Rect) {
    let base = match app.view {
        View::Approved => "Approved",
        View::Denied => "Denied",
        View::Pending => unreachable!(),
    };
    let title = format!(
        " {} · {} · {} ",
        base,
        app.rule_filter_label(),
        app.rules.len()
    );
    let block = Block::default()
        .title(panel_title(&title, true))
        .borders(Borders::ALL)
        .border_style(theme::border(false));

    if app.rules.is_empty() {
        let msg = Paragraph::new(format!(
            "\n  No {} rules in {}.\n  Press f to change the scope filter, or Tab to switch views.",
            base.to_lowercase(),
            app.rule_filter_label()
        ))
        .style(theme::text_muted())
        .block(block);
        f.render_widget(msg, area);
        return;
    }

    let cursor = app.rule_cursor;
    let items: Vec<ListItem> = app
        .rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let is_cursor = i == cursor;
            let (prefix, prefix_style) = if is_cursor {
                (" › ", theme::accent_strong())
            } else {
                ("   ", theme::text_muted())
            };
            let (sym, color) = rule_glyph(rule.rule_type);
            ListItem::new(Line::from(vec![
                Span::styled(prefix.to_string(), prefix_style),
                Span::styled(format!("{sym} "), Style::default().fg(color)),
                Span::styled(rule.pattern.clone(), theme::text_primary()),
                Span::styled(format!("   {}", scope_tag(rule.scope)), theme::text_muted()),
            ]))
        })
        .collect();

    let list = List::new(items).block(block);
    f.render_stateful_widget(list, area, &mut app.command_state);
}

fn rule_glyph(rule_type: RuleType) -> (&'static str, Color) {
    match rule_type {
        RuleType::Allow => ("✓", Color::Green),
        RuleType::Deny => ("✗", Color::Red),
        RuleType::Ask => ("?", Color::Yellow),
    }
}

fn scope_tag(scope: Scope) -> &'static str {
    match scope {
        Scope::User => "global",
        Scope::Project => "this project",
        Scope::Local => "local only",
    }
}

// === Decision panel (Pending) — the focal surface ===

fn draw_decision(f: &mut Frame, app: &App, area: Rect) {
    // The decision is what the user came here to make, so this panel always
    // carries the accent border and the airy rhythm; the list stays quiet.
    let border_style = theme::border(true);

    let Some(entry) = app.current_entry() else {
        let empty = Paragraph::new("\n  Select a command on the left to review it.")
            .style(theme::text_muted())
            .block(
                Block::default()
                    .title(panel_title(" Decision ", true))
                    .borders(Borders::ALL)
                    .border_style(border_style),
            );
        f.render_widget(empty, area);
        return;
    };

    let block = Block::default()
        .title(panel_title(" Decision ", true))
        .title_bottom(Line::from(message_spans(app)))
        .borders(Borders::ALL)
        .border_style(border_style);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let is_compound = entry.breakdown.len() > 1;
    let has_reason = app.current_reason().is_some();
    let has_tip = app.compound_tip().is_some();

    let mut constraints = vec![Constraint::Length(1)]; // command / segments
    if has_reason {
        constraints.push(Constraint::Length(1));
    }
    constraints.push(Constraint::Length(1)); // blank
    constraints.push(Constraint::Length(1)); // pattern
    constraints.push(Constraint::Length(2)); // scope + target
    constraints.push(Constraint::Length(2)); // blast radius
    if has_tip {
        constraints.push(Constraint::Length(1));
    }
    constraints.push(Constraint::Length(1)); // actions / confirm
    constraints.push(Constraint::Min(0));

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let mut idx = 0;

    if is_compound {
        draw_segments(f, app, entry, rows[idx]);
    } else {
        let decision = entry
            .breakdown
            .first()
            .map(|p| p.decision.as_str())
            .unwrap_or("ask");
        let line = Line::from(vec![
            Span::styled(
                format!(" {} ", theme::decision_symbol(decision)),
                Style::default().fg(theme::decision_color(decision)),
            ),
            Span::styled(entry.command.clone(), theme::text_strong()),
        ]);
        f.render_widget(Paragraph::new(line), rows[idx]);
    }
    idx += 1;

    if let Some(reason) = app.current_reason() {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::raw("   "),
                Span::styled(reason, theme::text_muted()),
            ])),
            rows[idx],
        );
        idx += 1;
    }

    idx += 1; // blank

    draw_pattern_row(f, app, rows[idx]);
    idx += 1;
    draw_scope_row(f, app, rows[idx]);
    idx += 1;
    draw_blast_radius(f, app, rows[idx]);
    idx += 1;

    if let Some(tip) = app.compound_tip() {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" i ", theme::accent()),
                Span::styled(tip, theme::text_muted()),
            ])),
            rows[idx],
        );
        idx += 1;
    }

    if app.confirm.is_some() {
        draw_confirm(f, app, rows[idx]);
    } else {
        draw_actions(f, app, rows[idx]);
    }
}

fn draw_segments(f: &mut Frame, app: &App, entry: &crate::pending::PendingApproval, area: Rect) {
    let actionable = app.actionable_segments();
    let operators = extract_operators(&entry.command);
    let mut spans: Vec<Span> = vec![Span::raw(" ")];

    for (i, part) in entry.breakdown.iter().enumerate() {
        if i > 0 {
            let op = operators.get(i - 1).copied().unwrap_or("&&");
            spans.push(Span::styled(format!("  {op}  "), theme::text_muted()));
        }
        let selected = actionable
            .iter()
            .position(|&ai| ai == i)
            .map(|ai| ai == app.selected_segment)
            .unwrap_or(false);
        let color = theme::decision_color(&part.decision);
        let sym = theme::decision_symbol(&part.decision);
        let text = segment_text(part);
        if selected {
            spans.push(Span::styled(
                format!("‹{sym} {text}›"),
                Style::default()
                    .fg(color)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ));
        } else {
            spans.push(Span::styled(
                format!("{sym} {text}"),
                Style::default().fg(color),
            ));
        }
    }
    f.render_widget(
        Paragraph::new(Line::from(spans)).wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_pattern_row(f: &mut Frame, app: &App, area: Rect) {
    let patterns = app.current_patterns();
    let pattern = patterns.get(app.selected_pattern);
    let description = pattern
        .map(|p| describe_pattern(p))
        .unwrap_or_else(|| "(no patterns)".to_string());
    let technical = pattern.map(|p| p.as_str()).unwrap_or("");
    let cyclable = patterns.len() > 1;
    let (lb, rb) = if cyclable { ("‹ ", " ›") } else { ("", "") };

    let line = Line::from(vec![
        Span::styled(" Pattern   ", theme::accent_strong()),
        Span::styled(format!("{lb}{description}{rb}"), theme::text_strong()),
        Span::styled(format!("   {technical}"), theme::text_muted()),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_scope_row(f: &mut Frame, app: &App, area: Rect) {
    let scope_text = match app.scope {
        Scope::User => "Global · all projects",
        Scope::Project => "This project · shared",
        Scope::Local => "This project · local only",
    };
    // Only the machine-wide choice gets the loud treatment.
    let value_style = match app.scope {
        Scope::User => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Scope::Local => Style::default().fg(Color::Green),
        Scope::Project => theme::text_strong(),
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(" Scope     ", theme::accent_strong()),
            Span::styled(format!("‹ {scope_text} ›"), value_style),
        ]),
        Line::from(vec![
            Span::styled("           → ", theme::text_muted()),
            Span::styled(app.target_path(), theme::text_muted()),
        ]),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

/// The signature: a two-axis blast-radius meter that fills and reddens as the
/// rule the user is about to write gets wider or farther-reaching.
fn draw_blast_radius(f: &mut Frame, app: &App, area: Rect) {
    let patterns = app.current_patterns();
    let pattern = patterns
        .get(app.selected_pattern)
        .cloned()
        .unwrap_or_default();
    let breadth = theme::pattern_breadth(&pattern);
    let reach = theme::scope_reach(app.scope);
    let risk = app.current_risk();
    let risk_color = risk.color();

    let tag = match risk {
        Risk::Danger => Span::styled(
            "  DANGER",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Risk::Caution => Span::raw(""),
        Risk::Safe => Span::styled("  safe", Style::default().fg(Color::Green)),
    };

    let p1 = format!(" {:<14}{:<8}", "Blast radius", "reach");
    let p2 = format!(" {:<14}{:<8}", "", "breadth");

    let reach_line = Line::from(vec![
        Span::styled(p1, theme::text_muted()),
        Span::styled(theme::meter(reach.level()), Style::default().fg(risk_color)),
        Span::raw(" "),
        Span::styled(reach.label(), theme::text_primary()),
    ]);
    let breadth_line = Line::from(vec![
        Span::styled(p2, theme::text_muted()),
        Span::styled(
            theme::meter(breadth.level()),
            Style::default().fg(risk_color),
        ),
        Span::raw(" "),
        Span::styled(breadth.label(), theme::text_primary()),
        tag,
    ]);

    f.render_widget(Paragraph::new(vec![reach_line, breadth_line]), area);
}

fn draw_actions(f: &mut Frame, app: &App, area: Rect) {
    let danger = app.current_risk() == Risk::Danger;
    let approve_text = if danger {
        " a Approve (confirm) "
    } else {
        " a Approve "
    };

    let line = Line::from(vec![
        Span::raw(" "),
        Span::styled(
            approve_text,
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("   "),
        Span::styled(" d Deny ", Style::default().fg(Color::Black).bg(Color::Red)),
        Span::raw("   "),
        Span::styled(" Del dismiss ", theme::text_muted()),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

/// The inline confirm prompt shared by the decision and rule panels.
fn confirm_line(app: &App) -> Line<'static> {
    let danger = Style::default().fg(Color::Red).add_modifier(Modifier::BOLD);
    Line::from(vec![
        Span::styled(" ⚠ ", danger),
        Span::styled(app.confirm_summary(), danger),
        Span::raw("   "),
        Span::styled(
            " y confirm ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled("any other key cancels", theme::text_muted()),
    ])
}

fn draw_confirm(f: &mut Frame, app: &App, area: Rect) {
    f.render_widget(Paragraph::new(confirm_line(app)), area);
}

// === Rule detail (Approved / Denied) ===

fn draw_rule_detail(f: &mut Frame, app: &App, area: Rect) {
    let border_style = theme::border(true);
    let block = Block::default()
        .title(panel_title(" Rule ", true))
        .title_bottom(Line::from(message_spans(app)))
        .borders(Borders::ALL)
        .border_style(border_style);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let Some(rule) = app.current_rule() else {
        f.render_widget(
            Paragraph::new("\n  No rule selected.").style(theme::text_muted()),
            inner,
        );
        return;
    };

    let (sym, color) = rule_glyph(rule.rule_type);
    let verb = if rule.rule_type == RuleType::Allow {
        "Allows"
    } else {
        "Blocks"
    };
    let effect = if rule.rule_type == RuleType::Allow {
        "Removing makes these commands prompt again."
    } else {
        "Removing lets these commands be requested again."
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!(" {sym} "), Style::default().fg(color)),
            Span::styled(rule.pattern.clone(), theme::text_strong()),
        ]),
        Line::from(vec![
            Span::styled("   ", theme::text_muted()),
            Span::styled(
                format!("{verb} {}", describe_pattern(&rule.pattern)),
                theme::text_muted(),
            ),
        ]),
        Line::from(Span::raw("")),
        Line::from(vec![
            Span::styled(" Scope     ", theme::accent_strong()),
            Span::styled(scope_tag(rule.scope), theme::text_strong()),
            Span::styled(format!("   → {}", rule_path(rule)), theme::text_muted()),
        ]),
        Line::from(Span::raw("")),
    ];

    if app.confirm.is_some() {
        lines.push(confirm_line(app));
    } else {
        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                " x Remove ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("   {effect}"), theme::text_muted()),
        ]));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn rule_path(rule: &RuleRow) -> String {
    let raw = match (&rule.project_cwd, rule.scope) {
        (Some(cwd), Scope::Local) => format!("{cwd}/.claude/settings.local.json"),
        (Some(cwd), _) => format!("{cwd}/.claude/settings.json"),
        (None, _) => Scope::User.path().to_string_lossy().to_string(),
    };
    collapse_home(&raw)
}

fn collapse_home(path: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        let home = home.to_string_lossy();
        if let Some(rest) = path.strip_prefix(home.as_ref()) {
            return format!("~{rest}");
        }
    }
    path.to_string()
}

fn message_spans(app: &App) -> Vec<Span<'static>> {
    let Some((msg, kind)) = &app.message else {
        return Vec::new();
    };
    let color = match kind {
        MessageKind::Success => Color::Green,
        MessageKind::Error => Color::Red,
        MessageKind::Info => Color::Yellow,
    };
    vec![
        Span::raw(" "),
        Span::styled(msg.clone(), Style::default().fg(color)),
        Span::raw(" "),
    ]
}

// === Footer ===

fn key(cap: &str) -> Span<'static> {
    Span::styled(cap.to_string(), theme::accent())
}

fn hint(text: &str) -> Span<'static> {
    Span::styled(text.to_string(), theme::text_muted())
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    if app.confirm.is_some() {
        let line = Line::from(vec![
            Span::styled(
                " y",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            hint(" confirm    "),
            key("esc"),
            hint(" cancel"),
        ]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }

    let mut spans = vec![Span::raw(" "), key("↑↓"), hint(" move  ")];

    if app.view == View::Pending {
        spans.push(key("←→"));
        spans.push(hint(" pattern  "));
        spans.push(key("s"));
        spans.push(hint(" scope  "));
        if app.current_entry().is_some_and(|e| e.breakdown.len() > 1) {
            spans.push(key("[ ]"));
            spans.push(hint(" seg  "));
        }
        spans.push(Span::styled(
            "a",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(hint(" approve  "));
        spans.push(Span::styled("d", Style::default().fg(Color::Red)));
        spans.push(hint(" deny  "));
        spans.push(key("Del"));
        spans.push(hint(" dismiss  "));
    } else {
        spans.push(key("↵/x"));
        spans.push(hint(" remove  "));
        spans.push(key("f"));
        spans.push(hint(&format!(" scope: {}  ", app.rule_filter_label())));
    }

    spans.push(key("Tab"));
    spans.push(hint(" view  "));
    spans.push(key("p"));
    spans.push(hint(" project  "));
    if app.can_undo() {
        spans.push(key("u"));
        spans.push(hint(" undo  "));
    }
    spans.push(key("q"));
    spans.push(hint(" quit"));

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

// === Project switcher overlay ===

fn draw_switcher(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = app.switcher_rows();
    let width = 54.min(area.width.saturating_sub(4));
    let height = (rows.len() as u16 + 2)
        .min(area.height.saturating_sub(2))
        .max(3);
    let popup = centered_rect(area, width, height);
    app.layout.switcher = popup;
    let avail = (popup.width as usize).saturating_sub(4);

    let items: Vec<ListItem> = rows
        .iter()
        .map(|r| switcher_row_item(app, r, avail))
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title(panel_title(" Switch project ", true))
            .borders(Borders::ALL)
            .border_style(theme::border(true)),
    );
    f.render_widget(Clear, popup);
    f.render_stateful_widget(list, popup, &mut app.sidebar_state);
}

fn switcher_row_item<'a>(app: &App, row: &SwitcherRow, avail: usize) -> ListItem<'a> {
    match row {
        SwitcherRow::Header(path) => ListItem::new(Line::from(Span::styled(
            format!(" {path}/"),
            theme::text_muted(),
        ))),
        SwitcherRow::Separator => {
            ListItem::new(Line::from(Span::styled("   ───────", theme::text_muted())))
        }
        SwitcherRow::Project(i) => {
            let p = &app.projects[*i];
            switcher_leaf(&p.name, p.count, *i == app.project_cursor, true, avail)
        }
        SwitcherRow::All => switcher_leaf(
            "All projects",
            app.entries.len(),
            app.project_cursor >= app.projects.len(),
            false,
            avail,
        ),
    }
}

fn switcher_leaf<'a>(
    name: &str,
    count: usize,
    selected: bool,
    indent: bool,
    avail: usize,
) -> ListItem<'a> {
    // Projects sit indented under their parent-dir header; "All" stays at the
    // top level.
    let prefix = match (indent, selected) {
        (true, true) => "   › ",
        (true, false) => "     ",
        (false, true) => " › ",
        (false, false) => "   ",
    };
    let name_style = if selected {
        theme::accent_strong()
    } else {
        theme::text_primary()
    };

    let count_str = format!(" ({count})");
    let max_name = avail.saturating_sub(count_str.len() + prefix.len() + 1);
    let shown = if name.chars().count() > max_name {
        let truncated: String = name.chars().take(max_name.saturating_sub(1)).collect();
        format!("{truncated}…")
    } else {
        name.to_string()
    };

    ListItem::new(Line::from(vec![
        Span::styled(prefix.to_string(), name_style),
        Span::styled(shown, name_style),
        Span::styled(count_str, theme::text_muted()),
    ]))
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    }
}

fn panel_title(text: &str, focused: bool) -> Span<'static> {
    if focused {
        Span::styled(text.to_string(), theme::accent_strong())
    } else {
        Span::styled(text.to_string(), theme::text_muted())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Decision;
    use crate::pending::PendingApproval;
    use crate::tracking::CommandPart;
    use ratatui::{Terminal, backend::TestBackend};

    fn part(program: &str, args: &[&str], decision: Decision) -> CommandPart {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        CommandPart::new(
            program,
            &args,
            decision,
            "Recursively force-deletes <path>.",
        )
    }

    fn pending(command: &str, patterns: &[&str], breakdown: Vec<CommandPart>) -> PendingApproval {
        PendingApproval::new(
            command.to_string(),
            patterns.iter().map(|s| s.to_string()).collect(),
            breakdown,
            "/home/u/proj".to_string(),
            "/home/u/proj".to_string(),
            "sess".to_string(),
        )
    }

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..h {
            for x in 0..w {
                out.push_str(buf.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "));
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn pending_view_shows_tabs_and_blast_radius() {
        let mut app = App::with_entries(vec![pending(
            "cargo nextest run",
            &["cargo nextest run", "cargo nextest:*", "cargo:*"],
            vec![part("cargo", &["nextest", "run"], Decision::Ask)],
        )]);
        let out = render(&mut app, 100, 26);
        assert!(out.contains("Pending"), "tab bar:\n{out}");
        assert!(out.contains("Approved"), "tab bar:\n{out}");
        assert!(out.contains("Decision"), "decision panel:\n{out}");
        assert!(out.contains("Blast"), "blast radius:\n{out}");
        println!("--- pending ---\n{out}");
    }

    #[test]
    fn compound_marks_danger_segment() {
        let mut app = App::with_entries(vec![pending(
            "rm -rf target && cargo build",
            &["rm:*"],
            vec![
                part("rm", &["-rf", "target"], Decision::Ask),
                part("cargo", &["build"], Decision::Allow),
            ],
        )]);
        let out = render(&mut app, 100, 26);
        assert!(out.contains('✓') && out.contains('?'), "glyphs:\n{out}");
        assert!(out.contains("DANGER"), "danger tag:\n{out}");
        println!("--- compound ---\n{out}");
    }

    #[test]
    fn approved_view_lists_rules() {
        let mut app = App::with_entries(vec![pending(
            "cargo build",
            &["cargo build:*"],
            vec![part("cargo", &["build"], Decision::Ask)],
        )]);
        // Inject rules directly to exercise the Approved view rendering.
        app.rules = vec![
            RuleRow {
                pattern: "cargo:*".to_string(),
                rule_type: RuleType::Allow,
                scope: Scope::User,
                project_cwd: None,
            },
            RuleRow {
                pattern: "git push:*".to_string(),
                rule_type: RuleType::Allow,
                scope: Scope::Project,
                project_cwd: Some("/home/u/proj".to_string()),
            },
        ];
        app.approved_count = 2;
        // Set the field directly so reload_rules doesn't clobber the injected list.
        app.view = View::Approved;
        let out = render(&mut app, 100, 26);
        assert!(
            out.contains("Approved · all scopes"),
            "title with filter:\n{out}"
        );
        assert!(
            out.contains("cargo:*") && out.contains("git push:*"),
            "rows:\n{out}"
        );
        assert!(out.contains("Remove"), "rule detail:\n{out}");
        assert!(out.contains("scope:"), "footer scope filter key:\n{out}");
        println!("--- approved ---\n{out}");
    }

    #[test]
    fn switcher_groups_projects_by_parent_dir() {
        let mut a = pending(
            "cargo build",
            &["cargo build:*"],
            vec![part("cargo", &["build"], Decision::Ask)],
        );
        a.cwd = "/srv/projects/alpha".to_string();
        let mut b = pending(
            "npm test",
            &["npm test:*"],
            vec![part("npm", &["test"], Decision::Ask)],
        );
        b.cwd = "/srv/projects/beta".to_string();
        let mut c = pending(
            "go test ./...",
            &["go test:*"],
            vec![part("go", &["test"], Decision::Ask)],
        );
        c.cwd = "/srv/work/gamma".to_string();

        let mut app = App::with_entries(vec![a, b, c]);
        app.open_switcher();
        let out = render(&mut app, 100, 26);
        assert!(out.contains("Switch project"), "title:\n{out}");
        assert!(
            out.contains("/srv/projects") && out.contains("/srv/work"),
            "parent-dir headers:\n{out}"
        );
        assert!(
            out.contains("alpha") && out.contains("beta") && out.contains("gamma"),
            "project leaves:\n{out}"
        );
        assert!(out.contains("All projects"), "all entry:\n{out}");
        println!("--- switcher tree ---\n{out}");
    }

    #[test]
    fn removing_a_rule_requires_confirmation() {
        let mut app = App::with_entries(vec![pending(
            "cargo build",
            &["cargo build:*"],
            vec![part("cargo", &["build"], Decision::Ask)],
        )]);
        app.rules = vec![RuleRow {
            pattern: "cargo:*".to_string(),
            rule_type: RuleType::Allow,
            scope: Scope::User,
            project_cwd: None,
        }];
        app.view = View::Approved;

        app.remove_selected_rule();
        assert!(
            app.confirm.is_some(),
            "x should arm a confirmation, not remove immediately"
        );

        let out = render(&mut app, 100, 26);
        assert!(out.contains("Remove approval cargo:*"), "summary:\n{out}");
        assert!(out.contains("y confirm"), "confirm prompt:\n{out}");
        println!("--- remove confirm ---\n{out}");

        // A non-y key cancels without touching the rule.
        app.confirm_cancel();
        assert!(app.confirm.is_none());
    }

    #[test]
    fn approving_a_segment_without_a_suggested_pattern_writes_nothing() {
        // A bare, argless high-stakes program (here `docker`) has no safe glob
        // to suggest. Selecting it in a compound and approving must refuse
        // rather than write a rule: there is no pattern the panel showed, so a
        // fabricated `program:*` grant would target the wrong program and skip
        // the risk confirm.
        let mut app = App::with_entries(vec![pending(
            "make && docker",
            &["make:*"],
            vec![
                part("make", &["build"], Decision::Allow),
                part("docker", &[], Decision::Ask),
            ],
        )]);
        // Only `docker` is actionable, and it has no suggested pattern.
        assert_eq!(app.actionable_segments().len(), 1);
        assert!(
            app.current_patterns().is_empty(),
            "bare docker should have no suggested pattern"
        );
        // Empty patterns must not silently downgrade to a no-confirm approve.
        assert_eq!(app.current_risk(), Risk::Caution);

        app.approve();
        assert!(
            matches!(app.message, Some((_, MessageKind::Error))),
            "approve must refuse when there is no pattern to write"
        );
        // The command stays in the queue; nothing was written or removed.
        assert_eq!(app.visible.len(), 1);
    }
}

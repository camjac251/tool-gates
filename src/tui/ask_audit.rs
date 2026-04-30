//! Multi-select checklist TUI for `tool-gates rules ask-audit --apply`.
//!
//! The CLI's per-rule [y/N] sequence forces a strict-order commitment;
//! this checklist lets the user toggle freely before applying. Up/Down
//! navigates, Space toggles, Enter applies the selection, q/Esc cancels.

use crate::settings_writer::PermissionRule;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};
use std::io;
use std::panic::AssertUnwindSafe;

/// Run the checklist. Returns the indices of rules the user marked for
/// removal, or `None` if they cancelled. The caller is responsible for
/// the actual `remove_rule` calls so this module stays UI-only.
pub fn run_ask_audit_checklist(rules: &[&PermissionRule]) -> io::Result<Option<Vec<usize>>> {
    if rules.is_empty() {
        return Ok(Some(Vec::new()));
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let size = terminal.size()?;
    if size.width < 60 || size.height < 14 {
        let _ = disable_raw_mode();
        let _ = execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        eprintln!(
            "Terminal too small ({}x{}). Need at least 60x14.",
            size.width, size.height
        );
        return Ok(None);
    }

    let mut state = ChecklistState::new(rules.len());

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        run_loop(&mut terminal, rules, &mut state)
    }));

    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = terminal.show_cursor();

    match result {
        Ok(io_result) => io_result,
        Err(panic_payload) => std::panic::resume_unwind(panic_payload),
    }
}

struct ChecklistState {
    cursor: usize,
    selected: Vec<bool>,
    list_state: ListState,
}

impl ChecklistState {
    fn new(n: usize) -> Self {
        let mut list_state = ListState::default();
        if n > 0 {
            list_state.select(Some(0));
        }
        Self {
            cursor: 0,
            selected: vec![false; n],
            list_state,
        }
    }

    fn count_selected(&self) -> usize {
        self.selected.iter().filter(|s| **s).count()
    }
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    rules: &[&PermissionRule],
    state: &mut ChecklistState,
) -> io::Result<Option<Vec<usize>>> {
    loop {
        terminal.draw(|f| draw(f, rules, state))?;

        if let Event::Key(key) = event::read()? {
            match (key.code, key.modifiers) {
                (KeyCode::Esc, _) | (KeyCode::Char('q'), KeyModifiers::NONE) => {
                    return Ok(None);
                }
                (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                    return Ok(None);
                }
                (KeyCode::Up, _) | (KeyCode::Char('k'), KeyModifiers::NONE) if state.cursor > 0 => {
                    state.cursor -= 1;
                    state.list_state.select(Some(state.cursor));
                }
                (KeyCode::Down, _) | (KeyCode::Char('j'), KeyModifiers::NONE)
                    if state.cursor + 1 < rules.len() =>
                {
                    state.cursor += 1;
                    state.list_state.select(Some(state.cursor));
                }
                (KeyCode::Char(' '), _) => {
                    if let Some(slot) = state.selected.get_mut(state.cursor) {
                        *slot = !*slot;
                    }
                }
                (KeyCode::Char('a'), KeyModifiers::NONE) => {
                    let all_set = state.selected.iter().all(|s| *s);
                    for s in state.selected.iter_mut() {
                        *s = !all_set;
                    }
                }
                (KeyCode::Enter, _) => {
                    let chosen: Vec<usize> = state
                        .selected
                        .iter()
                        .enumerate()
                        .filter_map(|(i, sel)| if *sel { Some(i) } else { None })
                        .collect();
                    return Ok(Some(chosen));
                }
                _ => {}
            }
        }
    }
}

fn draw(f: &mut Frame, rules: &[&PermissionRule], state: &mut ChecklistState) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(0),    // list
            Constraint::Length(3), // footer
        ])
        .split(area);

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " ask-audit ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!(
                "{} of {} rule(s) marked for removal",
                state.count_selected(),
                rules.len()
            ),
            Style::default().fg(Color::White),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(header, chunks[0]);

    let items: Vec<ListItem> = rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let is_selected = state.selected.get(i).copied().unwrap_or(false);
            let marker = if is_selected { "[x]" } else { "[ ]" };
            let marker_style = if is_selected {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            let pattern_style = if i == state.cursor {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {} ", marker), marker_style),
                Span::styled(rule.pattern.clone(), pattern_style),
                Span::raw("  "),
                Span::styled(
                    format!("({} scope)", rule.scope.as_str()),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title(" Gate-covered rules (Space toggles) ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_stateful_widget(list, chunks[1], &mut state.list_state);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" ↑/↓ ", Style::default().fg(Color::Cyan)),
        Span::raw("nav  "),
        Span::styled("Space ", Style::default().fg(Color::Cyan)),
        Span::raw("toggle  "),
        Span::styled("a ", Style::default().fg(Color::Cyan)),
        Span::raw("toggle all  "),
        Span::styled("Enter ", Style::default().fg(Color::Cyan)),
        Span::raw("apply  "),
        Span::styled("Esc/q ", Style::default().fg(Color::Cyan)),
        Span::raw("cancel"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(footer, chunks[2]);
}

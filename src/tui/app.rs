//! Application state and event handling for the review TUI.

use crate::models::CommandInfo;
use crate::patterns::suggest_patterns;
use crate::pending::{
    PendingApproval, ProjectInfo, append_pending, category_weight, derive_projects, read_pending,
    remove_pending_many,
};
use crate::settings_writer::{
    RuleType, Scope, add_rule, add_rule_to_project, list_rules, list_rules_for_project,
    parse_pattern, remove_rule, remove_rule_from_project,
};
use crate::tracking::CommandPart;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseButton,
        MouseEventKind,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend, layout::Rect, widgets::ListState};
use std::io;
use std::panic::AssertUnwindSafe;

use super::theme::{self, Risk};
use super::ui;

/// Which list the review is showing. Tab cycles between them; arrows only ever
/// move within the active list, so a key never changes meaning by focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Pending,
    Approved,
    Denied,
}

/// Status message type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Success,
    Error,
    Info,
}

/// A consequential action armed and waiting for an explicit `y`. Routing
/// removal through here means a stray keypress while navigating can't delete a
/// rule: any key other than `y` cancels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmKind {
    Approve,
    Deny,
    RemoveRule,
}

/// One rendered row of the project-switcher tree.
#[derive(Debug, Clone)]
pub enum SwitcherRow {
    /// Parent directory grouping label; not selectable.
    Header(String),
    /// A project, indexed into `projects`.
    Project(usize),
    /// Visual divider before "All".
    Separator,
    /// The "all projects" entry.
    All,
}

/// An existing permission rule shown in the Approved / Denied views.
#[derive(Debug, Clone)]
pub struct RuleRow {
    /// Unwrapped pattern (no `Bash(...)`).
    pub pattern: String,
    pub rule_type: RuleType,
    pub scope: Scope,
    /// Project directory for project/local rules; `None` for global.
    pub project_cwd: Option<String>,
}

/// Enough state to reverse the last action.
#[derive(Debug, Clone)]
enum LastAction {
    Wrote {
        entry: PendingApproval,
        pattern: String,
        scope: Scope,
        rule_type: RuleType,
    },
    Dismissed {
        entry: PendingApproval,
    },
    RemovedRule {
        pattern: String,
        rule_type: RuleType,
        scope: Scope,
        project_cwd: Option<String>,
    },
}

/// Rendered layout areas for mouse hit-testing
#[derive(Debug, Clone, Copy, Default)]
pub struct LayoutAreas {
    pub commands: Rect,
    pub detail: Rect,
    /// The project-switcher popup, when open.
    pub switcher: Rect,
}

/// Application state
pub struct App {
    // Data
    pub entries: Vec<PendingApproval>,
    pub projects: Vec<ProjectInfo>,
    /// Index into projects; projects.len() means "All".
    pub project_cursor: usize,

    /// Active list.
    pub view: View,

    // Pending list
    pub visible: Vec<usize>,
    pub command_cursor: usize,
    pub selected_segment: usize,
    pub selected_pattern: usize,
    pub scope: Scope,

    // Rules list (Approved / Denied)
    pub rules: Vec<RuleRow>,
    pub rule_cursor: usize,
    pub approved_count: usize,
    pub denied_count: usize,
    /// Scope filter for the rules views; `None` shows every scope.
    pub rule_scope_filter: Option<Scope>,

    // Scroll state (command_state drives both the pending and rule lists)
    pub command_state: ListState,
    pub sidebar_state: ListState,

    // UI state
    pub should_quit: bool,
    pub message: Option<(String, MessageKind)>,
    pub layout: LayoutAreas,
    pub show_switcher: bool,
    pub confirm: Option<ConfirmKind>,
    last_action: Option<LastAction>,
}

impl App {
    pub fn new(show_all: bool) -> Self {
        let entries = read_pending(None);
        let projects = derive_projects(&entries);

        let project_cursor = if show_all || projects.is_empty() {
            projects.len()
        } else {
            detect_current_project(&projects).unwrap_or(projects.len())
        };

        let scope = if project_cursor < projects.len() {
            Scope::Project
        } else {
            Scope::User
        };

        let mut app = Self {
            entries,
            projects,
            project_cursor,
            view: View::Pending,
            visible: Vec::new(),
            command_cursor: 0,
            selected_segment: 0,
            selected_pattern: 0,
            scope,
            rules: Vec::new(),
            rule_cursor: 0,
            approved_count: 0,
            denied_count: 0,
            rule_scope_filter: None,
            command_state: ListState::default(),
            sidebar_state: ListState::default(),
            should_quit: false,
            message: None,
            layout: LayoutAreas::default(),
            show_switcher: false,
            confirm: None,
            last_action: None,
        };
        app.sync_sidebar_state();
        app.update_visible();
        app.reload_rules();
        app
    }

    /// Recompute visible pending commands based on the selected project.
    pub fn update_visible(&mut self) {
        let filter_display = if self.project_cursor < self.projects.len() {
            Some(self.projects[self.project_cursor].display_path.clone())
        } else {
            None
        };

        let mut indices: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                filter_display
                    .as_ref()
                    .is_none_or(|dp| crate::pending::display_project_path(e) == *dp)
            })
            .map(|(i, _)| i)
            .collect();

        indices.sort_by(|&a, &b| {
            let ea = &self.entries[a];
            let eb = &self.entries[b];
            let wa = category_weight(&ea.command);
            let wb = category_weight(&eb.command);
            wa.cmp(&wb).then(eb.count.cmp(&ea.count))
        });

        self.visible = indices;
        self.command_cursor = 0;
        if self.view == View::Pending {
            self.command_state.select(if self.visible.is_empty() {
                None
            } else {
                Some(0)
            });
        }
        self.reset_detail();
    }

    fn reset_detail(&mut self) {
        self.selected_segment = 0;
        self.selected_pattern = self.default_pattern_index();
    }

    /// Smartest-by-risk default: narrowest pattern for high-stakes programs,
    /// the tightest family glob for safe tools.
    fn default_pattern_index(&self) -> usize {
        let patterns = self.current_patterns();
        if patterns.is_empty() {
            return 0;
        }
        if theme::is_high_stakes(&self.current_program()) {
            return 0;
        }
        patterns
            .iter()
            .position(|p| theme::pattern_breadth(p) == theme::Breadth::Scoped)
            .unwrap_or(0)
    }

    pub fn current_entry(&self) -> Option<&PendingApproval> {
        self.visible
            .get(self.command_cursor)
            .and_then(|&idx| self.entries.get(idx))
    }

    pub fn current_rule(&self) -> Option<&RuleRow> {
        self.rules.get(self.rule_cursor)
    }

    pub fn is_all_view(&self) -> bool {
        self.project_cursor >= self.projects.len()
    }

    pub fn total_pending(&self) -> usize {
        self.entries.len()
    }

    pub fn project_name(&self) -> String {
        if self.is_all_view() {
            "all projects".to_string()
        } else if let Some(p) = self.projects.get(self.project_cursor) {
            p.name.clone()
        } else {
            "unknown".to_string()
        }
    }

    pub fn actionable_segments(&self) -> Vec<usize> {
        self.current_entry()
            .map(|e| {
                e.breakdown
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| p.decision == "ask")
                    .map(|(i, _)| i)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn current_patterns(&self) -> Vec<String> {
        let Some(entry) = self.current_entry() else {
            return Vec::new();
        };
        if entry.breakdown.len() <= 1 {
            return entry.patterns.clone();
        }
        let actionable = self.actionable_segments();
        if let Some(&seg_idx) = actionable.get(self.selected_segment) {
            if let Some(part) = entry.breakdown.get(seg_idx) {
                return segment_patterns(part);
            }
        }
        entry.patterns.clone()
    }

    pub fn current_reason(&self) -> Option<String> {
        let entry = self.current_entry()?;
        if entry.breakdown.len() <= 1 {
            return entry
                .breakdown
                .first()
                .filter(|p| !p.reason.is_empty())
                .map(|p| p.reason.clone());
        }
        let actionable = self.actionable_segments();
        actionable.get(self.selected_segment).and_then(|&idx| {
            entry
                .breakdown
                .get(idx)
                .filter(|p| !p.reason.is_empty())
                .map(|p| p.reason.clone())
        })
    }

    /// Program that drives the risk of the rule about to be written.
    fn current_program(&self) -> String {
        let Some(entry) = self.current_entry() else {
            return String::new();
        };
        if entry.breakdown.len() > 1 {
            let actionable = self.actionable_segments();
            if let Some(&idx) = actionable.get(self.selected_segment) {
                if let Some(part) = entry.breakdown.get(idx) {
                    return part.program.clone();
                }
            }
        }
        entry
            .breakdown
            .first()
            .map(|p| p.program.clone())
            .unwrap_or_else(|| {
                entry
                    .command
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
    }

    pub fn current_risk(&self) -> Risk {
        let patterns = self.current_patterns();
        let Some(pattern) = patterns.get(self.selected_pattern) else {
            return Risk::Caution;
        };
        theme::assess_risk(pattern, self.scope, &self.current_program())
    }

    /// Target settings file for the current scope, home-collapsed.
    pub fn target_path(&self) -> String {
        match self.scope {
            Scope::User => {
                let path = Scope::User.path();
                if let Some(home) = dirs::home_dir() {
                    path.to_string_lossy()
                        .replacen(&home.to_string_lossy().to_string(), "~", 1)
                } else {
                    path.to_string_lossy().to_string()
                }
            }
            Scope::Project | Scope::Local => {
                if let Some(entry) = self.current_entry() {
                    let filename = if self.scope == Scope::Project {
                        "settings.json"
                    } else {
                        "settings.local.json"
                    };
                    let display = crate::pending::display_project_path(entry);
                    format!("{}/.claude/{}", display, filename)
                } else {
                    "(no command selected)".to_string()
                }
            }
        }
    }

    pub fn compound_tip(&self) -> Option<String> {
        let entry = self.current_entry()?;
        if entry.breakdown.len() <= 1 {
            return None;
        }
        let allowed_count = entry
            .breakdown
            .iter()
            .filter(|p| p.decision == "allow")
            .count();
        let ask_count = entry
            .breakdown
            .iter()
            .filter(|p| p.decision == "ask")
            .count();
        if ask_count == 1 && allowed_count > 0 {
            let allowed_names: Vec<_> = entry
                .breakdown
                .iter()
                .filter(|p| p.decision == "allow")
                .map(|p| format!("\"{}\"", p.program))
                .collect();
            Some(format!(
                "Approving covers the whole command since {} already allowed.",
                allowed_names.join(", ")
            ))
        } else if ask_count > 1 {
            Some(format!(
                "This command has {} parts needing approval.",
                ask_count
            ))
        } else {
            None
        }
    }

    // === Navigation (flat: arrows always move within the active list) ===

    pub fn move_cursor(&mut self, down: bool) {
        match self.view {
            View::Pending => {
                if self.visible.is_empty() {
                    return;
                }
                self.command_cursor = step(self.command_cursor, self.visible.len(), down);
                self.command_state.select(Some(self.command_cursor));
                self.reset_detail();
            }
            View::Approved | View::Denied => {
                if self.rules.is_empty() {
                    return;
                }
                self.rule_cursor = step(self.rule_cursor, self.rules.len(), down);
                self.command_state.select(Some(self.rule_cursor));
            }
        }
    }

    /// Change the pattern breadth for the selected pending command.
    pub fn cycle_pattern(&mut self, forward: bool) {
        if self.view != View::Pending {
            return;
        }
        let count = self.current_patterns().len();
        if count == 0 {
            return;
        }
        self.selected_pattern = step(self.selected_pattern, count, forward);
    }

    /// Cycle the write scope (local / project / global).
    pub fn cycle_scope(&mut self, forward: bool) {
        if self.view != View::Pending {
            return;
        }
        self.scope = if forward {
            match self.scope {
                Scope::User => Scope::Project,
                Scope::Project => Scope::Local,
                Scope::Local => Scope::User,
            }
        } else {
            match self.scope {
                Scope::User => Scope::Local,
                Scope::Project => Scope::User,
                Scope::Local => Scope::Project,
            }
        };
    }

    /// Cycle which segment of a compound command is being approved.
    pub fn cycle_segment(&mut self, forward: bool) {
        if self.view != View::Pending {
            return;
        }
        let actionable = self.actionable_segments();
        if actionable.len() <= 1 {
            return;
        }
        self.selected_segment = step(self.selected_segment, actionable.len(), forward);
        self.selected_pattern = self.default_pattern_index();
    }

    // === Views ===

    pub fn set_view(&mut self, view: View) {
        if self.view == view {
            return;
        }
        self.view = view;
        self.rule_cursor = 0;
        match view {
            View::Pending => {
                self.command_state.select(if self.visible.is_empty() {
                    None
                } else {
                    Some(self.command_cursor)
                });
            }
            View::Approved | View::Denied => {
                self.reload_rules();
            }
        }
    }

    pub fn cycle_view(&mut self, forward: bool) {
        let next = match (self.view, forward) {
            (View::Pending, true) => View::Approved,
            (View::Approved, true) => View::Denied,
            (View::Denied, true) => View::Pending,
            (View::Pending, false) => View::Denied,
            (View::Approved, false) => View::Pending,
            (View::Denied, false) => View::Approved,
        };
        self.set_view(next);
    }

    /// Cycle the rules-view scope filter: all → global → project → local.
    pub fn cycle_rule_filter(&mut self) {
        if self.view == View::Pending {
            return;
        }
        self.rule_scope_filter = match self.rule_scope_filter {
            None => Some(Scope::User),
            Some(Scope::User) => Some(Scope::Project),
            Some(Scope::Project) => Some(Scope::Local),
            Some(Scope::Local) => None,
        };
        self.rule_cursor = 0;
        self.reload_rules();
    }

    pub fn rule_filter_label(&self) -> &'static str {
        match self.rule_scope_filter {
            None => "all scopes",
            Some(Scope::User) => "global",
            Some(Scope::Project) => "this project",
            Some(Scope::Local) => "local",
        }
    }

    fn selected_project_cwd(&self) -> Option<String> {
        self.projects
            .get(self.project_cursor)
            .map(|p| p.cwd.clone())
    }

    /// Read every reachable rule (global + selected project) once.
    fn gather_all_rules(&self) -> Vec<RuleRow> {
        let mut rows = Vec::new();
        for r in list_rules(Scope::User) {
            if r.rule_type != RuleType::Ask {
                rows.push(RuleRow {
                    pattern: parse_pattern(&r.pattern),
                    rule_type: r.rule_type,
                    scope: Scope::User,
                    project_cwd: None,
                });
            }
        }
        if let Some(cwd) = self.selected_project_cwd() {
            for scope in [Scope::Project, Scope::Local] {
                for r in list_rules_for_project(scope, &cwd) {
                    if r.rule_type != RuleType::Ask {
                        rows.push(RuleRow {
                            pattern: parse_pattern(&r.pattern),
                            rule_type: r.rule_type,
                            scope,
                            project_cwd: Some(cwd.clone()),
                        });
                    }
                }
            }
        }
        rows
    }

    fn reload_rules(&mut self) {
        let all = self.gather_all_rules();
        self.approved_count = all
            .iter()
            .filter(|r| r.rule_type == RuleType::Allow)
            .count();
        self.denied_count = all.iter().filter(|r| r.rule_type == RuleType::Deny).count();

        let want = match self.view {
            View::Approved => Some(RuleType::Allow),
            View::Denied => Some(RuleType::Deny),
            View::Pending => None,
        };
        let mut rows: Vec<RuleRow> = match want {
            Some(t) => all.into_iter().filter(|r| r.rule_type == t).collect(),
            None => Vec::new(),
        };
        if let Some(filter) = self.rule_scope_filter {
            rows.retain(|r| r.scope == filter);
        }
        // Group by scope (global, then project, then local), pattern within.
        rows.sort_by(|a, b| {
            scope_order(a.scope)
                .cmp(&scope_order(b.scope))
                .then_with(|| a.pattern.cmp(&b.pattern))
        });
        self.rules = rows;

        if self.rule_cursor >= self.rules.len() {
            self.rule_cursor = self.rules.len().saturating_sub(1);
        }
        if self.view != View::Pending {
            self.command_state.select(if self.rules.is_empty() {
                None
            } else {
                Some(self.rule_cursor)
            });
        }
    }

    // === Actions ===

    pub fn approve(&mut self) {
        if self.view != View::Pending || self.current_entry().is_none() {
            return;
        }
        if theme::requires_confirm(self.current_risk()) {
            self.confirm = Some(ConfirmKind::Approve);
        } else {
            self.do_approve(RuleType::Allow);
        }
    }

    pub fn deny(&mut self) {
        if self.view == View::Pending && self.current_entry().is_some() {
            self.confirm = Some(ConfirmKind::Deny);
        }
    }

    /// Clear a command from the queue without writing any rule.
    pub fn dismiss(&mut self) {
        if self.view != View::Pending {
            return;
        }
        let Some(entry) = self.current_entry().cloned() else {
            return;
        };
        if let Err(e) = remove_pending_many(std::slice::from_ref(&entry.id)) {
            self.message = Some((format!("Failed to dismiss: {e}"), MessageKind::Error));
            return;
        }
        self.last_action = Some(LastAction::Dismissed { entry });
        self.message = Some(("Dismissed · u to undo".to_string(), MessageKind::Info));
        self.refresh();
    }

    /// Arm the remove-rule confirmation for the selected rule.
    pub fn remove_selected_rule(&mut self) {
        if self.view != View::Pending && self.current_rule().is_some() {
            self.confirm = Some(ConfirmKind::RemoveRule);
        }
    }

    fn do_remove_rule(&mut self) {
        let Some(rule) = self.current_rule().cloned() else {
            return;
        };
        let res = match (rule.scope, &rule.project_cwd) {
            (Scope::User, _) => remove_rule(Scope::User, &rule.pattern),
            (scope, Some(cwd)) => remove_rule_from_project(scope, cwd, &rule.pattern),
            (scope, None) => remove_rule(scope, &rule.pattern),
        };
        match res {
            Ok(_) => {
                let verb = if rule.rule_type == RuleType::Allow {
                    "approval"
                } else {
                    "deny rule"
                };
                self.message = Some((
                    format!("Removed {verb} {} · u to undo", rule.pattern),
                    MessageKind::Info,
                ));
                self.last_action = Some(LastAction::RemovedRule {
                    pattern: rule.pattern,
                    rule_type: rule.rule_type,
                    scope: rule.scope,
                    project_cwd: rule.project_cwd,
                });
                self.reload_rules();
            }
            Err(e) => self.message = Some((format!("Remove failed: {e}"), MessageKind::Error)),
        }
    }

    pub fn confirm_yes(&mut self) {
        match self.confirm.take() {
            Some(ConfirmKind::Approve) => self.do_approve(RuleType::Allow),
            Some(ConfirmKind::Deny) => self.do_approve(RuleType::Deny),
            Some(ConfirmKind::RemoveRule) => self.do_remove_rule(),
            None => {}
        }
    }

    pub fn confirm_cancel(&mut self) {
        if self.confirm.take().is_some() {
            self.message = Some(("Cancelled".to_string(), MessageKind::Info));
        }
    }

    pub fn can_undo(&self) -> bool {
        self.last_action.is_some()
    }

    pub fn confirm_summary(&self) -> String {
        match self.confirm {
            Some(ConfirmKind::Approve) => {
                let patterns = self.current_patterns();
                let pattern = patterns
                    .get(self.selected_pattern)
                    .cloned()
                    .unwrap_or_default();
                format!(
                    "Approve {} for {}",
                    pattern,
                    theme::scope_reach(self.scope).label()
                )
            }
            Some(ConfirmKind::Deny) => {
                let patterns = self.current_patterns();
                let pattern = patterns
                    .get(self.selected_pattern)
                    .cloned()
                    .unwrap_or_default();
                format!("Deny (block) {}", pattern)
            }
            Some(ConfirmKind::RemoveRule) => match self.current_rule() {
                Some(rule) => {
                    let verb = if rule.rule_type == RuleType::Allow {
                        "approval"
                    } else {
                        "deny rule"
                    };
                    format!(
                        "Remove {verb} {} ({})",
                        rule.pattern,
                        scope_label(rule.scope)
                    )
                }
                None => String::new(),
            },
            None => String::new(),
        }
    }

    fn do_approve(&mut self, rule_type: RuleType) {
        let Some(entry) = self.current_entry().cloned() else {
            return;
        };
        let patterns = self.current_patterns();
        let Some(pattern) = patterns.get(self.selected_pattern).cloned() else {
            // A segment with no suggested pattern (e.g. a bare, argless program
            // that has no safe glob) must not be auto-approved. Refusing keeps
            // the written rule identical to what the panel showed and stops a
            // broad `program:*` grant from being fabricated and skipping the
            // risk confirm.
            self.message = Some((
                "No suggested pattern for this segment; use `tool-gates approve` if intended"
                    .to_string(),
                MessageKind::Error,
            ));
            return;
        };

        if let Err(msg) = self.write_rule(&pattern, &entry, rule_type) {
            self.message = Some((msg, MessageKind::Error));
            return;
        }
        if let Err(e) = remove_pending_many(std::slice::from_ref(&entry.id)) {
            self.message = Some((
                format!("Failed to remove from queue: {e}"),
                MessageKind::Error,
            ));
            return;
        }

        let action = if rule_type == RuleType::Allow {
            "Approved"
        } else {
            "Denied"
        };
        self.last_action = Some(LastAction::Wrote {
            entry,
            pattern: pattern.clone(),
            scope: self.scope,
            rule_type,
        });
        self.message = Some((
            format!(
                "{action} {pattern} → {} · u to undo",
                scope_label(self.scope)
            ),
            MessageKind::Success,
        ));
        self.refresh();
    }

    fn write_rule(
        &self,
        pattern: &str,
        entry: &PendingApproval,
        rule_type: RuleType,
    ) -> Result<(), String> {
        match self.scope {
            Scope::User => {
                add_rule(Scope::User, pattern, rule_type).map_err(|e| format!("User: {e}"))
            }
            scope @ (Scope::Project | Scope::Local) => {
                let cwd = if entry.cwd.is_empty() {
                    &entry.project_id
                } else {
                    &entry.cwd
                };
                add_rule_to_project(scope, cwd, pattern, rule_type)
                    .map_err(|e| format!("{}: {e}", cwd))
            }
        }
    }

    pub fn undo(&mut self) {
        let Some(action) = self.last_action.take() else {
            self.message = Some(("Nothing to undo".to_string(), MessageKind::Info));
            return;
        };
        match action {
            LastAction::Wrote {
                entry,
                pattern,
                scope,
                rule_type,
            } => {
                let removed = match scope {
                    Scope::User => remove_rule(Scope::User, &pattern),
                    s @ (Scope::Project | Scope::Local) => {
                        let cwd = if entry.cwd.is_empty() {
                            entry.project_id.clone()
                        } else {
                            entry.cwd.clone()
                        };
                        remove_rule_from_project(s, &cwd, &pattern)
                    }
                };
                if let Err(e) = removed {
                    self.message = Some((format!("Undo failed: {e}"), MessageKind::Error));
                    return;
                }
                let _ = append_pending(entry);
                let verb = if rule_type == RuleType::Deny {
                    "deny"
                } else {
                    "approval"
                };
                self.message = Some((format!("Reverted {verb} of {pattern}"), MessageKind::Info));
            }
            LastAction::Dismissed { entry } => {
                let _ = append_pending(entry);
                self.message = Some(("Restored dismissed command".to_string(), MessageKind::Info));
            }
            LastAction::RemovedRule {
                pattern,
                rule_type,
                scope,
                project_cwd,
            } => {
                let res = match (scope, &project_cwd) {
                    (Scope::User, _) => add_rule(Scope::User, &pattern, rule_type),
                    (s, Some(cwd)) => add_rule_to_project(s, cwd, &pattern, rule_type),
                    (s, None) => add_rule(s, &pattern, rule_type),
                };
                if let Err(e) = res {
                    self.message = Some((format!("Undo failed: {e}"), MessageKind::Error));
                    return;
                }
                self.message = Some((format!("Restored rule {pattern}"), MessageKind::Info));
            }
        }
        self.refresh();
    }

    fn refresh(&mut self) {
        let old_project = if self.project_cursor < self.projects.len() {
            Some(self.projects[self.project_cursor].display_path.clone())
        } else {
            None
        };

        self.entries = read_pending(None);
        self.projects = derive_projects(&self.entries);

        if let Some(old_dp) = old_project {
            self.project_cursor = self
                .projects
                .iter()
                .position(|p| p.display_path == old_dp)
                .unwrap_or(self.projects.len());
        }

        self.update_visible();
        self.reload_rules();
        self.sync_sidebar_state();
    }

    fn sync_sidebar_state(&mut self) {
        // Point the list at the rendered row of the selected project so it
        // scrolls into view; headers and the separator shift the index.
        let rows = self.switcher_rows();
        let idx = rows
            .iter()
            .position(|r| match r {
                SwitcherRow::Project(i) => *i == self.project_cursor,
                SwitcherRow::All => self.project_cursor >= self.projects.len(),
                _ => false,
            })
            .unwrap_or(0);
        self.sidebar_state.select(Some(idx));
    }

    // === Project switcher overlay ===

    pub fn open_switcher(&mut self) {
        self.show_switcher = true;
        self.sync_sidebar_state();
    }

    pub fn close_switcher(&mut self) {
        self.show_switcher = false;
    }

    /// Projects grouped by parent directory into a tree of rendered rows.
    pub fn switcher_rows(&self) -> Vec<SwitcherRow> {
        let mut order: Vec<usize> = (0..self.projects.len()).collect();
        order.sort_by(|&a, &b| {
            let pa = parent_of(&self.projects[a].display_path);
            let pb = parent_of(&self.projects[b].display_path);
            pa.cmp(&pb)
                .then_with(|| self.projects[a].name.cmp(&self.projects[b].name))
        });

        let mut rows = Vec::new();
        let mut last_parent: Option<String> = None;
        for &i in &order {
            let parent = parent_of(&self.projects[i].display_path);
            if last_parent.as_deref() != Some(parent.as_str()) {
                rows.push(SwitcherRow::Header(parent.clone()));
                last_parent = Some(parent);
            }
            rows.push(SwitcherRow::Project(i));
        }
        if !self.projects.is_empty() {
            rows.push(SwitcherRow::Separator);
        }
        rows.push(SwitcherRow::All);
        rows
    }

    /// `project_cursor` values for the selectable rows, in display order.
    fn switcher_selectables(&self) -> Vec<usize> {
        self.switcher_rows()
            .iter()
            .filter_map(|r| match r {
                SwitcherRow::Project(i) => Some(*i),
                SwitcherRow::All => Some(self.projects.len()),
                _ => None,
            })
            .collect()
    }

    pub fn switcher_nav(&mut self, down: bool) {
        let sels = self.switcher_selectables();
        if sels.is_empty() {
            return;
        }
        let cur = sels
            .iter()
            .position(|&p| p == self.project_cursor)
            .unwrap_or(0);
        self.project_cursor = sels[step(cur, sels.len(), down)];
        self.sync_sidebar_state();
        self.on_project_changed();
    }

    fn on_project_changed(&mut self) {
        self.scope = if self.is_all_view() {
            Scope::User
        } else {
            Scope::Project
        };
        self.update_visible();
        self.reload_rules();
    }

    pub fn handle_mouse_click(&mut self, col: u16, row: u16) {
        let la = self.layout;

        if self.show_switcher {
            if in_rect(la.switcher, col, row) {
                let clicked =
                    (row.saturating_sub(la.switcher.y + 1)) as usize + self.sidebar_state.offset();
                let rows = self.switcher_rows();
                match rows.get(clicked) {
                    Some(SwitcherRow::Project(i)) => {
                        self.project_cursor = *i;
                        self.sync_sidebar_state();
                        self.on_project_changed();
                        self.show_switcher = false;
                    }
                    Some(SwitcherRow::All) => {
                        self.project_cursor = self.projects.len();
                        self.sync_sidebar_state();
                        self.on_project_changed();
                        self.show_switcher = false;
                    }
                    // Header / separator / out of range: ignore.
                    _ => {}
                }
            } else {
                self.show_switcher = false;
            }
            return;
        }

        if in_rect(la.commands, col, row) {
            let clicked =
                (row.saturating_sub(la.commands.y + 1)) as usize + self.command_state.offset();
            match self.view {
                View::Pending => {
                    if clicked < self.visible.len() {
                        self.command_cursor = clicked;
                        self.command_state.select(Some(clicked));
                        self.reset_detail();
                    }
                }
                View::Approved | View::Denied => {
                    if clicked < self.rules.len() {
                        self.rule_cursor = clicked;
                        self.command_state.select(Some(clicked));
                    }
                }
            }
        }
    }
}

// === Helpers ===

/// Parent directory of a display path, for grouping projects in the switcher.
/// `~/projects/alpha` -> `~/projects`. A path with no parent returns itself.
fn parent_of(display_path: &str) -> String {
    match display_path.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => parent.to_string(),
        _ => display_path.to_string(),
    }
}

/// Sort order for grouping rules by scope: global, then project, then local.
fn scope_order(scope: Scope) -> u8 {
    match scope {
        Scope::User => 0,
        Scope::Project => 1,
        Scope::Local => 2,
    }
}

/// Step a wrapping cursor in a list of `len`.
fn step(cursor: usize, len: usize, down: bool) -> usize {
    if len == 0 {
        return 0;
    }
    if down {
        (cursor + 1) % len
    } else if cursor == 0 {
        len - 1
    } else {
        cursor - 1
    }
}

#[cfg(test)]
impl App {
    /// Build an App from in-memory entries without touching disk. Test-only.
    pub(crate) fn with_entries(entries: Vec<PendingApproval>) -> Self {
        let projects = derive_projects(&entries);
        let mut app = Self {
            entries,
            projects,
            project_cursor: 0,
            view: View::Pending,
            visible: Vec::new(),
            command_cursor: 0,
            selected_segment: 0,
            selected_pattern: 0,
            scope: Scope::Project,
            rules: Vec::new(),
            rule_cursor: 0,
            approved_count: 0,
            denied_count: 0,
            rule_scope_filter: None,
            command_state: ListState::default(),
            sidebar_state: ListState::default(),
            should_quit: false,
            message: None,
            layout: LayoutAreas::default(),
            show_switcher: false,
            confirm: None,
            last_action: None,
        };
        app.sync_sidebar_state();
        app.update_visible();
        app
    }
}

fn detect_current_project(projects: &[ProjectInfo]) -> Option<usize> {
    let cwd = std::env::current_dir().ok()?;
    let cwd_str = cwd.to_string_lossy();
    projects
        .iter()
        .position(|p| cwd_str == p.cwd.as_str() || cwd_str.starts_with(&format!("{}/", p.cwd)))
}

fn segment_patterns(part: &CommandPart) -> Vec<String> {
    let cmd = CommandInfo {
        raw: if part.args.is_empty() {
            part.program.clone()
        } else {
            format!("{} {}", part.program, part.args.join(" "))
        },
        program: part.program.clone(),
        args: part.args.clone(),
        scratch_vars: Default::default(),
    };
    suggest_patterns(&cmd)
}

fn scope_label(scope: Scope) -> &'static str {
    match scope {
        Scope::User => "global",
        Scope::Project => "project",
        Scope::Local => "local",
    }
}

fn in_rect(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
}

/// Describe a pattern in plain language (action-neutral wording).
pub fn describe_pattern(pattern: &str) -> String {
    if let Some(base) = pattern.strip_suffix(":*") {
        format!("All \"{}\" commands", base)
    } else if let Some(rest) = pattern.strip_suffix('*') {
        format!("\"{}...\" commands", rest.trim_end())
    } else {
        format!("\"{}\" exactly", pattern)
    }
}

/// Extract operators from a raw compound command for display.
/// NOTE: Does not respect quoting. Operators inside strings will be matched.
/// This is display-only; the actual parsing uses tree-sitter and is correct.
pub fn extract_operators(raw: &str) -> Vec<&str> {
    let mut ops = Vec::new();
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'&' && bytes[i + 1] == b'&' {
            ops.push("&&");
            i += 2;
        } else if i + 1 < bytes.len() && bytes[i] == b'|' && bytes[i + 1] == b'|' {
            ops.push("||");
            i += 2;
        } else if bytes[i] == b'|' {
            ops.push("|");
            i += 1;
        } else if bytes[i] == b';' {
            ops.push(";");
            i += 1;
        } else {
            i += 1;
        }
    }
    ops
}

// === Entry point ===

/// Run the review TUI
pub fn run_review(show_all: bool) -> io::Result<()> {
    let mut app = App::new(show_all);

    if app.entries.is_empty() && app.approved_count == 0 && app.denied_count == 0 {
        eprintln!("No pending approvals and no rules to manage.");
        return Ok(());
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let size = terminal.size()?;
    if size.width < 60 || size.height < 20 {
        let _ = disable_raw_mode();
        let _ = execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        eprintln!(
            "Terminal too small ({}x{}). Need at least 60x20.",
            size.width, size.height
        );
        return Ok(());
    }

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| run_app(&mut terminal, &mut app)));

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

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> io::Result<()>
where
    io::Error: From<B::Error>,
{
    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        if app.should_quit {
            return Ok(());
        }

        if event::poll(std::time::Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) if key.kind == event::KeyEventKind::Press => {
                    if app.confirm.is_some() {
                        // y commits the armed action; any other key cancels.
                        match key.code {
                            KeyCode::Char('y') | KeyCode::Char('Y') => app.confirm_yes(),
                            _ => app.confirm_cancel(),
                        }
                    } else if app.show_switcher {
                        match key.code {
                            KeyCode::Down | KeyCode::Char('j') => app.switcher_nav(true),
                            KeyCode::Up | KeyCode::Char('k') => app.switcher_nav(false),
                            KeyCode::Enter
                            | KeyCode::Char(' ')
                            | KeyCode::Esc
                            | KeyCode::Char('p')
                            | KeyCode::Char('q') => app.close_switcher(),
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                app.should_quit = true;
                            }

                            // Views
                            KeyCode::Tab => app.cycle_view(true),
                            KeyCode::BackTab => app.cycle_view(false),
                            KeyCode::Char('1') => app.set_view(View::Pending),
                            KeyCode::Char('2') => app.set_view(View::Approved),
                            KeyCode::Char('3') => app.set_view(View::Denied),

                            // Project switcher
                            KeyCode::Char('p') => app.open_switcher(),

                            // Scope filter (rules views)
                            KeyCode::Char('f') => app.cycle_rule_filter(),

                            // Navigation (arrows always move within the active list)
                            KeyCode::Down | KeyCode::Char('j') => app.move_cursor(true),
                            KeyCode::Up | KeyCode::Char('k') => app.move_cursor(false),

                            // Pattern breadth (pending)
                            KeyCode::Left | KeyCode::Char('h') => app.cycle_pattern(false),
                            KeyCode::Right | KeyCode::Char('l') => app.cycle_pattern(true),

                            // Scope (pending)
                            KeyCode::Char('s') => app.cycle_scope(true),
                            KeyCode::Char('S') => app.cycle_scope(false),

                            // Compound segment (pending)
                            KeyCode::Char('[') => app.cycle_segment(false),
                            KeyCode::Char(']') => app.cycle_segment(true),

                            // Undo
                            KeyCode::Char('u') => app.undo(),

                            // Actions (letter keys; Enter kept as an approve alias)
                            KeyCode::Char('a') => app.approve(),
                            KeyCode::Enter => {
                                if app.view == View::Pending {
                                    app.approve();
                                } else {
                                    app.remove_selected_rule();
                                }
                            }
                            KeyCode::Char('d') => app.deny(),
                            KeyCode::Char('x') | KeyCode::Delete | KeyCode::Backspace => {
                                if app.view == View::Pending {
                                    app.dismiss();
                                } else {
                                    app.remove_selected_rule();
                                }
                            }

                            _ => {}
                        }
                    }
                }
                Event::Mouse(mouse) if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                    app.handle_mouse_click(mouse.column, mouse.row);
                }
                _ => {}
            }
        }
    }
}

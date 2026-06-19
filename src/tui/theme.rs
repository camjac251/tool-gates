//! Semantic style tokens, decision/risk symbols, and blast-radius scoring
//! for the review TUI.
//!
//! Every color the UI draws routes through this module so the rest of the
//! rendering code never reaches for a raw `Color::`. Text roles are
//! `Color::Reset`-relative (they inherit the terminal's own foreground), so
//! the interface stays legible on light and dark terminals alike. Decisions
//! and risk carry a symbol in addition to a hue, so the encoding survives
//! no-color terminals and color blindness.

use crate::settings_writer::Scope;
use ratatui::style::{Color, Modifier, Style};

// === Text roles ===

/// Default body text. Inherits the terminal foreground.
pub fn text_primary() -> Style {
    Style::default().fg(Color::Reset)
}

/// Emphasized text: the value the eye should land on.
pub fn text_strong() -> Style {
    Style::default()
        .fg(Color::Reset)
        .add_modifier(Modifier::BOLD)
}

/// Supporting text: labels, counts, paths. Dimmed default-fg adapts to theme.
pub fn text_muted() -> Style {
    Style::default()
        .fg(Color::Reset)
        .add_modifier(Modifier::DIM)
}

/// Focus / interactive accent.
pub fn accent() -> Style {
    Style::default().fg(Color::Cyan)
}

/// Strong focus accent (focused borders, brand).
pub fn accent_strong() -> Style {
    Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

/// Border style for a panel.
pub fn border(focused: bool) -> Style {
    if focused {
        accent_strong()
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

// === Decisions (per-segment allow / ask / block) ===

/// A glyph that disambiguates the decision without relying on color.
pub fn decision_symbol(decision: &str) -> &'static str {
    match decision {
        "allow" => "✓",
        "block" => "✗",
        _ => "?", // ask / skip / unknown
    }
}

pub fn decision_color(decision: &str) -> Color {
    match decision {
        "allow" => Color::Green,
        "block" => Color::Red,
        _ => Color::Yellow,
    }
}

// === Blast radius ===

/// How consequential writing this rule is. Drives color and whether the
/// approve action demands an explicit confirmation keystroke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    Safe,
    Caution,
    Danger,
}

impl Risk {
    pub fn color(self) -> Color {
        match self {
            Risk::Safe => Color::Green,
            Risk::Caution => Color::Yellow,
            Risk::Danger => Color::Red,
        }
    }
}

/// How wide the pattern is: one command, a family, or an entire program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Breadth {
    Exact,
    Scoped,
    Broad,
}

impl Breadth {
    /// 0..=2, used both for the meter fill and for risk scoring.
    pub fn level(self) -> u8 {
        match self {
            Breadth::Exact => 0,
            Breadth::Scoped => 1,
            Breadth::Broad => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Breadth::Exact => "this command only",
            Breadth::Scoped => "a family of commands",
            Breadth::Broad => "every subcommand",
        }
    }
}

/// Classify how wide a settings pattern is. `pattern` is the un-wrapped form
/// (no `Bash(...)` wrapper), e.g. `git push:*`, `cargo:*`, `npm run test`.
pub fn pattern_breadth(pattern: &str) -> Breadth {
    let p = pattern.trim();
    if let Some(base) = p.strip_suffix(":*") {
        // "git push:*" scopes to a subcommand; "cargo:*" is the whole program.
        if base.contains(' ') {
            Breadth::Scoped
        } else {
            Breadth::Broad
        }
    } else if p.ends_with('*') {
        // Prefix or domain glob: "npm run test*", "curl *github.com*".
        Breadth::Scoped
    } else {
        Breadth::Exact
    }
}

/// How far the rule reaches: just you, the whole team, or the whole machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    Local,
    Project,
    Global,
}

impl Reach {
    pub fn level(self) -> u8 {
        match self {
            Reach::Local => 0,
            Reach::Project => 1,
            Reach::Global => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Reach::Local => "only you, this project",
            Reach::Project => "everyone on this project",
            Reach::Global => "every project on this machine",
        }
    }
}

pub fn scope_reach(scope: Scope) -> Reach {
    match scope {
        Scope::Local => Reach::Local,
        Scope::Project => Reach::Project,
        Scope::User => Reach::Global,
    }
}

/// Programs that stay high-stakes even with a narrow pattern: network egress,
/// arbitrary execution, privilege escalation, destructive filesystem ops, and
/// infra control planes. Approving any glob over one of these is a Danger.
pub fn is_high_stakes(program: &str) -> bool {
    matches!(
        program,
        "curl"
            | "wget"
            | "xh"
            | "http"
            | "nc"
            | "ncat"
            | "socat"
            | "telnet"
            | "ssh"
            | "scp"
            | "sftp"
            | "rsync"
            | "bash"
            | "sh"
            | "zsh"
            | "fish"
            | "eval"
            | "source"
            | "exec"
            | "sudo"
            | "doas"
            | "su"
            | "rm"
            | "dd"
            | "mkfs"
            | "shred"
            | "chmod"
            | "chown"
            | "npx"
            | "uvx"
            | "pipx"
            | "docker"
            | "kubectl"
            | "helm"
            | "terraform"
            | "pulumi"
            | "aws"
            | "gcloud"
            | "az"
    )
}

/// Assess the risk of writing `pattern` at `scope` for a rule whose primary
/// program is `program`. Bias is to safe: only genuinely wide or high-stakes
/// writes reach Danger (the level that demands confirmation).
pub fn assess_risk(pattern: &str, scope: Scope, program: &str) -> Risk {
    let breadth = pattern_breadth(pattern);
    let reach = scope_reach(scope);
    let stakes = is_high_stakes(program);

    // Danger floor: anything wider than one command applied to every project,
    // a high-stakes command reaching every project, or a whole-program glob
    // over a high-stakes tool.
    let danger = (reach == Reach::Global && (breadth != Breadth::Exact || stakes))
        || (stakes && breadth == Breadth::Broad);
    if danger {
        return Risk::Danger;
    }

    let score = breadth.level() + reach.level() + u8::from(stakes);
    if score >= 1 {
        Risk::Caution
    } else {
        Risk::Safe
    }
}

/// Whether approving at this risk level should require an explicit confirm.
pub fn requires_confirm(risk: Risk) -> bool {
    risk == Risk::Danger
}

/// Render a 3-cell meter (e.g. `▰▰▱`) filled to `level` (0..=2), colored for
/// the risk at that fill.
pub fn meter(level: u8) -> String {
    let level = level.min(2) as usize;
    let mut cells = String::new();
    for i in 0..3 {
        cells.push(if i <= level { '▰' } else { '▱' });
    }
    cells
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breadth_classifies_exact_scoped_broad() {
        assert_eq!(pattern_breadth("npm install lodash"), Breadth::Exact);
        assert_eq!(pattern_breadth("git push:*"), Breadth::Scoped);
        assert_eq!(pattern_breadth("npm run test*"), Breadth::Scoped);
        assert_eq!(pattern_breadth("cargo:*"), Breadth::Broad);
    }

    #[test]
    fn safe_is_exact_local_low_stakes() {
        assert_eq!(assess_risk("git status", Scope::Local, "git"), Risk::Safe);
    }

    #[test]
    fn global_glob_is_danger() {
        assert_eq!(assess_risk("cargo:*", Scope::User, "cargo"), Risk::Danger);
        assert_eq!(assess_risk("git push:*", Scope::User, "git"), Risk::Danger);
    }

    #[test]
    fn broad_glob_over_high_stakes_is_danger_even_local() {
        assert_eq!(assess_risk("curl:*", Scope::Local, "curl"), Risk::Danger);
        assert_eq!(
            assess_risk("docker:*", Scope::Project, "docker"),
            Risk::Danger
        );
    }

    #[test]
    fn project_subcommand_glob_is_caution_not_danger() {
        assert_eq!(
            assess_risk("cargo build:*", Scope::Project, "cargo"),
            Risk::Caution
        );
        assert_eq!(
            assess_risk("cargo:*", Scope::Project, "cargo"),
            Risk::Caution
        );
    }

    #[test]
    fn exact_high_stakes_local_is_caution() {
        // A single pinned curl to one host, local only, should not nag.
        assert_eq!(
            assess_risk("curl *api.example.com*", Scope::Local, "curl"),
            Risk::Caution
        );
    }

    #[test]
    fn confirm_only_on_danger() {
        assert!(requires_confirm(Risk::Danger));
        assert!(!requires_confirm(Risk::Caution));
        assert!(!requires_confirm(Risk::Safe));
    }

    #[test]
    fn meter_fills_to_level() {
        assert_eq!(meter(0), "▰▱▱");
        assert_eq!(meter(1), "▰▰▱");
        assert_eq!(meter(2), "▰▰▰");
    }
}

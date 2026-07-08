//! Permission gates for different command categories.
//!
//! Gates use a hybrid approach:
//! 1. Try declarative rules first (from generated code)
//! 2. Fall back to custom handlers for complex logic

pub mod basics;
pub mod beads;
pub mod cloud;
pub mod devtools;
pub mod filesystem;
pub mod gh;
pub mod git;
pub mod helpers;
pub mod network;
pub mod package_managers;
pub mod runtimes;
pub mod shortcut;
pub mod system;
pub mod tool_gates;

#[cfg(test)]
pub mod test_utils;

pub use basics::check_basics;
pub use beads::check_beads;
pub use cloud::check_cloud;
pub use devtools::check_devtools;
pub use filesystem::check_filesystem;
pub use gh::check_gh;
pub use git::check_git;
pub use network::check_network;
pub use package_managers::check_package_managers;
pub use runtimes::check_runtimes;
pub use shortcut::check_shortcut;
pub use system::check_system;
pub use tool_gates::check_tool_gates;

use crate::models::{CommandInfo, Decision, GateResult};

/// Type alias for gate check functions
pub type GateCheckFn = fn(&CommandInfo) -> GateResult;

/// All gates to run (in order)
/// basics runs last as a catch-all for safe commands
pub static GATES: &[(&str, GateCheckFn)] = &[
    ("gh", check_gh),
    ("git", check_git),
    ("cloud", check_cloud),
    ("package_managers", check_package_managers),
    ("beads", check_beads),
    ("tool_gates", check_tool_gates),
    ("devtools", check_devtools),
    ("runtimes", check_runtimes),
    ("filesystem", check_filesystem),
    ("network", check_network),
    ("system", check_system),
    ("shortcut", check_shortcut),
    ("basics", check_basics),
];

/// Check a single command against all gates.
pub fn check_single_command(cmd: &crate::models::CommandInfo) -> GateResult {
    let mut strictest = GateResult::skip();

    for (_gate_name, gate_func) in GATES {
        let result = gate_func(cmd);

        // Track the strictest decision (Block > Ask > Allow > Skip)
        if result.decision > strictest.decision {
            strictest = result;
        }

        // Early return on Block (can't get stricter)
        if strictest.decision == Decision::Block {
            return strictest;
        }
    }

    strictest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics_gate_runs_last() {
        assert_eq!(
            GATES.last().map(|(name, _)| *name),
            Some("basics"),
            "basics must be the final gate (catch-all for safe commands)"
        );
    }

    #[test]
    fn every_rules_toml_has_a_registered_gate() {
        // The gate registry key is the rules file STEM: build.rs generates
        // check_<stem>_gate and GATES lists <stem>. ([meta].name is a
        // human-readable display label, not the key.) Guards the "added
        // rules/<x>.toml but forgot to register check_<x> in GATES" failure,
        // which otherwise silently falls through to skip.
        let manifest = env!("CARGO_MANIFEST_DIR");
        let rules_dir = std::path::Path::new(manifest).join("rules");
        let registered: std::collections::HashSet<&str> =
            GATES.iter().map(|(name, _)| *name).collect();

        for entry in std::fs::read_dir(&rules_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_else(|| panic!("{}: non-utf8 filename", path.display()));
            assert!(
                registered.contains(stem),
                "rules/{stem}.toml has no registered gate in GATES",
            );
        }
    }
}

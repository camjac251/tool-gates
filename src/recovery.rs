//! Client-aware rendering for provider-neutral recovery guidance.
//!
//! Gates attach semantic [`RecoveryAction`] values to a hook decision. The
//! selected client's serializer renders those actions only when producing the
//! wire response, using the file-tool registry as the capability source.

use crate::file_tools::read_tool_for_client;
use crate::models::Client;

/// The portion of a confirmed source file that the blocked command requested.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FileSelection {
    /// The first number of lines.
    First(u64),
    /// The last number of lines.
    Last(u64),
    /// The complete file, or a selection that cannot be represented exactly.
    Whole,
}

/// A recovery step whose client-specific wording is deferred to serialization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RecoveryAction {
    /// Inspect a confirmed single source file without piping it through a cap.
    ReadSourceFile { selection: FileSelection },
    /// Preserve every row or byte returned by the producer.
    KeepCompleteOutput,
    /// Apply a producer-side limit, optionally naming a known producer.
    UseProducerNativeLimit { producer: Option<String> },
    /// Run the producer without a downstream cap.
    RunUncapped,
    /// Run uncapped and persist the complete output for later range inspection.
    RunUncappedAndPersist,
    /// Use a meaningful filter that does not impose a downstream count limit.
    FilterByRealPattern,
}

/// Render recovery steps with the capabilities and vocabulary of `client`.
///
/// Duplicate actions are emitted once in first-seen order. A client with a
/// registered read tool gets that native tool name; otherwise the renderer
/// gives a conditional, portable shell example rather than claiming a tool is
/// available.
pub fn render_recovery_actions(client: Client, actions: &[RecoveryAction]) -> String {
    render_recovery_actions_for(Some(client), actions)
}

/// Render recovery for a surface with no active hook client, such as the WASM
/// simulator. File selections remain actionable without naming any client's
/// native tool or assuming a shell utility is installed.
pub fn render_neutral_recovery_actions(actions: &[RecoveryAction]) -> String {
    render_recovery_actions_for(None, actions)
}

fn render_recovery_actions_for(client: Option<Client>, actions: &[RecoveryAction]) -> String {
    let mut seen = std::collections::HashSet::new();
    actions
        .iter()
        .filter(|action| seen.insert(*action))
        .map(|action| match action {
            RecoveryAction::ReadSourceFile { selection } => {
                if client.is_none() {
                    match selection {
                        FileSelection::First(lines) => format!(
                            "Inspect the first {lines} lines of the source file directly."
                        ),
                        FileSelection::Last(lines) => format!(
                            "Inspect the last {lines} lines of the source file directly."
                        ),
                        FileSelection::Whole => {
                            "Inspect the source file directly.".to_string()
                        }
                    }
                } else if let Some(tool) = client.and_then(read_tool_for_client) {
                    match selection {
                        FileSelection::First(lines) => format!(
                            "Use the `{tool}` tool to inspect the first {lines} lines of the source file directly."
                        ),
                        FileSelection::Last(lines) => format!(
                            "Use the `{tool}` tool to inspect the last {lines} lines of the source file directly."
                        ),
                        FileSelection::Whole => format!(
                            "Use the `{tool}` tool to inspect the source file directly."
                        ),
                    }
                } else {
                    match selection {
                        FileSelection::First(lines) => format!(
                            "Inspect the first {lines} lines directly from the source file. If `bat` is available, use `bat -r :{lines} <file>`."
                        ),
                        FileSelection::Last(lines) => format!(
                            "Inspect the last {lines} lines directly from the source file. If `bat` is available, use `bat -r -{lines}: <file>`."
                        ),
                        FileSelection::Whole => "Inspect the source file directly. If `bat` is available, use `bat <file>`.".to_string(),
                    }
                }
            }
            RecoveryAction::KeepCompleteOutput => "Keep the complete output.".to_string(),
            RecoveryAction::UseProducerNativeLimit { producer: None } => {
                "Use the producer's native limit when the task needs a bounded result.".to_string()
            }
            RecoveryAction::UseProducerNativeLimit {
                producer: Some(producer),
            } => format!(
                "Use `{producer}`'s native options when the task needs a bounded result."
            ),
            RecoveryAction::RunUncapped => "Run the command uncapped.".to_string(),
            RecoveryAction::RunUncappedAndPersist => {
                "Otherwise run uncapped and persist the complete output for range inspection."
                    .to_string()
            }
            RecoveryAction::FilterByRealPattern => {
                "If the task needs matching lines, filter with a real pattern without limiting the stream."
                    .to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Client;

    #[test]
    fn registered_clients_render_their_native_file_reader() {
        let actions = [RecoveryAction::ReadSourceFile {
            selection: FileSelection::First(10),
        }];

        for (client, tool) in [
            (Client::Claude, "Read"),
            (Client::Gemini, "read_file"),
            (Client::Antigravity, "view_file"),
        ] {
            assert_eq!(
                render_recovery_actions(client, &actions),
                format!(
                    "Use the `{tool}` tool to inspect the first 10 lines of the source file directly."
                )
            );
        }
    }

    #[test]
    fn codex_renders_conditional_shell_range_examples() {
        for (selection, expected) in [
            (
                FileSelection::First(12),
                "Inspect the first 12 lines directly from the source file. If `bat` is available, use `bat -r :12 <file>`.",
            ),
            (
                FileSelection::Last(7),
                "Inspect the last 7 lines directly from the source file. If `bat` is available, use `bat -r -7: <file>`.",
            ),
            (
                FileSelection::Whole,
                "Inspect the source file directly. If `bat` is available, use `bat <file>`.",
            ),
        ] {
            assert_eq!(
                render_recovery_actions(
                    Client::Codex,
                    &[RecoveryAction::ReadSourceFile { selection }]
                ),
                expected
            );
        }
    }

    #[test]
    fn clientless_surfaces_render_file_recovery_without_tool_vocabulary() {
        for (selection, expected) in [
            (
                FileSelection::First(12),
                "Inspect the first 12 lines of the source file directly.",
            ),
            (
                FileSelection::Last(7),
                "Inspect the last 7 lines of the source file directly.",
            ),
            (FileSelection::Whole, "Inspect the source file directly."),
        ] {
            assert_eq!(
                render_neutral_recovery_actions(&[RecoveryAction::ReadSourceFile { selection }]),
                expected
            );
        }
    }

    #[test]
    fn non_file_recovery_actions_stay_client_neutral() {
        let cases = [
            (
                RecoveryAction::KeepCompleteOutput,
                "Keep the complete output.",
            ),
            (
                RecoveryAction::UseProducerNativeLimit { producer: None },
                "Use the producer's native limit when the task needs a bounded result.",
            ),
            (
                RecoveryAction::UseProducerNativeLimit {
                    producer: Some("gh".to_string()),
                },
                "Use `gh`'s native options when the task needs a bounded result.",
            ),
            (RecoveryAction::RunUncapped, "Run the command uncapped."),
            (
                RecoveryAction::RunUncappedAndPersist,
                "Otherwise run uncapped and persist the complete output for range inspection.",
            ),
            (
                RecoveryAction::FilterByRealPattern,
                "If the task needs matching lines, filter with a real pattern without limiting the stream.",
            ),
        ];

        for client in [
            Client::Claude,
            Client::Gemini,
            Client::Codex,
            Client::Antigravity,
        ] {
            for (action, expected) in &cases {
                assert_eq!(
                    render_recovery_actions(client, std::slice::from_ref(action)),
                    *expected
                );
            }
        }
    }

    #[test]
    fn duplicate_recovery_actions_render_once_in_first_seen_order() {
        let native_limit = RecoveryAction::UseProducerNativeLimit { producer: None };
        let actions = [
            native_limit.clone(),
            RecoveryAction::RunUncappedAndPersist,
            native_limit,
        ];

        assert_eq!(
            render_recovery_actions(Client::Claude, &actions),
            "Use the producer's native limit when the task needs a bounded result. Otherwise run uncapped and persist the complete output for range inspection."
        );
    }
}

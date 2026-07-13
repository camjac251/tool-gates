//! Canonical file-tool registry shared by classification and hook generation.

use crate::models::Client;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilePayloadKind {
    FilePath,
    ReadMany,
    Content,
    Replacement,
    Notebook,
    ApplyPatch,
    NormalizedContent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileHookEvent {
    PreToolUse,
    PermissionRequest,
    PostToolUse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileToolSpec {
    pub client: Client,
    pub name: &'static str,
    pub access: FileAccess,
    pub payload: FilePayloadKind,
    pub permission_request: bool,
    pub post_tool_use: bool,
}

pub const FILE_TOOL_SPECS: &[FileToolSpec] = &[
    FileToolSpec {
        client: Client::Claude,
        name: "Read",
        access: FileAccess::Read,
        payload: FilePayloadKind::FilePath,
        permission_request: false,
        post_tool_use: false,
    },
    FileToolSpec {
        client: Client::Claude,
        name: "Write",
        access: FileAccess::Write,
        payload: FilePayloadKind::Content,
        permission_request: true,
        post_tool_use: true,
    },
    FileToolSpec {
        client: Client::Claude,
        name: "Edit",
        access: FileAccess::Write,
        payload: FilePayloadKind::Replacement,
        permission_request: true,
        post_tool_use: true,
    },
    FileToolSpec {
        client: Client::Claude,
        name: "NotebookEdit",
        access: FileAccess::Write,
        payload: FilePayloadKind::Notebook,
        permission_request: true,
        post_tool_use: true,
    },
    FileToolSpec {
        client: Client::Gemini,
        name: "read_file",
        access: FileAccess::Read,
        payload: FilePayloadKind::FilePath,
        permission_request: false,
        post_tool_use: false,
    },
    FileToolSpec {
        client: Client::Gemini,
        name: "read_many_files",
        access: FileAccess::Read,
        payload: FilePayloadKind::ReadMany,
        permission_request: false,
        post_tool_use: false,
    },
    FileToolSpec {
        client: Client::Gemini,
        name: "write_file",
        access: FileAccess::Write,
        payload: FilePayloadKind::Content,
        permission_request: false,
        post_tool_use: false,
    },
    FileToolSpec {
        client: Client::Gemini,
        name: "replace",
        access: FileAccess::Write,
        payload: FilePayloadKind::Replacement,
        permission_request: false,
        post_tool_use: false,
    },
    FileToolSpec {
        client: Client::Codex,
        name: "apply_patch",
        access: FileAccess::Write,
        payload: FilePayloadKind::ApplyPatch,
        permission_request: true,
        post_tool_use: true,
    },
    FileToolSpec {
        client: Client::Antigravity,
        name: "view_file",
        access: FileAccess::Read,
        payload: FilePayloadKind::FilePath,
        permission_request: false,
        post_tool_use: false,
    },
    FileToolSpec {
        client: Client::Antigravity,
        name: "write_to_file",
        access: FileAccess::Write,
        payload: FilePayloadKind::NormalizedContent,
        permission_request: false,
        post_tool_use: false,
    },
    FileToolSpec {
        client: Client::Antigravity,
        name: "replace_file_content",
        access: FileAccess::Write,
        payload: FilePayloadKind::NormalizedContent,
        permission_request: false,
        post_tool_use: false,
    },
    FileToolSpec {
        client: Client::Antigravity,
        name: "multi_replace_file_content",
        access: FileAccess::Write,
        payload: FilePayloadKind::NormalizedContent,
        permission_request: false,
        post_tool_use: false,
    },
];

pub fn spec_for_name(tool_name: &str) -> Option<&'static FileToolSpec> {
    FILE_TOOL_SPECS.iter().find(|spec| spec.name == tool_name)
}

pub fn is_file_tool(tool_name: &str) -> bool {
    spec_for_name(tool_name).is_some()
}

pub fn is_read_tool(tool_name: &str) -> bool {
    spec_for_name(tool_name).is_some_and(|spec| spec.access == FileAccess::Read)
}

pub fn is_write_tool(tool_name: &str) -> bool {
    spec_for_name(tool_name).is_some_and(|spec| spec.access == FileAccess::Write)
}

pub fn hook_names(client: Client, event: FileHookEvent) -> impl Iterator<Item = &'static str> {
    FILE_TOOL_SPECS
        .iter()
        .filter(move |spec| {
            spec.client == client
                && match event {
                    FileHookEvent::PreToolUse => true,
                    FileHookEvent::PermissionRequest => spec.permission_request,
                    FileHookEvent::PostToolUse => spec.post_tool_use,
                }
        })
        .map(|spec| spec.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn tool_names_are_unique_and_classification_is_consistent() {
        let mut names = HashSet::new();
        for spec in FILE_TOOL_SPECS {
            assert!(
                names.insert(spec.name),
                "duplicate file tool: {}",
                spec.name
            );
            assert!(is_file_tool(spec.name));
            assert!(
                is_read_tool(spec.name) || is_write_tool(spec.name),
                "{} must have one access class",
                spec.name
            );
            assert_ne!(is_read_tool(spec.name), is_write_tool(spec.name));
        }
    }

    #[test]
    fn hook_membership_matches_each_client_contract() {
        assert_eq!(
            hook_names(Client::Claude, FileHookEvent::PreToolUse).collect::<Vec<_>>(),
            ["Read", "Write", "Edit", "NotebookEdit"]
        );
        assert_eq!(
            hook_names(Client::Claude, FileHookEvent::PermissionRequest).collect::<Vec<_>>(),
            ["Write", "Edit", "NotebookEdit"]
        );
        assert_eq!(
            hook_names(Client::Gemini, FileHookEvent::PostToolUse).collect::<Vec<_>>(),
            Vec::<&str>::new()
        );
        assert_eq!(
            hook_names(Client::Codex, FileHookEvent::PostToolUse).collect::<Vec<_>>(),
            ["apply_patch"]
        );
        assert_eq!(
            hook_names(Client::Antigravity, FileHookEvent::PreToolUse).collect::<Vec<_>>(),
            [
                "view_file",
                "write_to_file",
                "replace_file_content",
                "multi_replace_file_content"
            ]
        );
    }
}

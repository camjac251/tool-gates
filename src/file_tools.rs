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

/// Return the client's canonical single-file reader, when one is registered.
pub fn read_tool_for_client(client: Client) -> Option<&'static str> {
    FILE_TOOL_SPECS
        .iter()
        .find(|spec| {
            spec.client == client
                && spec.access == FileAccess::Read
                && spec.payload == FilePayloadKind::FilePath
        })
        .map(|spec| spec.name)
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

/// Parsed view of one file-tool payload. Codex patches are parsed once when
/// this context is created and reused for malformed checks, paths, and content.
pub struct ParsedFileInput<'a> {
    spec: &'static FileToolSpec,
    map: &'a serde_json::Map<String, serde_json::Value>,
    patch_files: Option<Vec<crate::apply_patch_parser::PatchedFile>>,
}

impl<'a> ParsedFileInput<'a> {
    pub fn new(
        tool_name: &str,
        map: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Option<Self> {
        let spec = spec_for_name(tool_name)?;
        let patch_files = (spec.payload == FilePayloadKind::ApplyPatch).then(|| {
            crate::apply_patch_parser::parse_patch(
                map.get("command")
                    .and_then(|value| value.as_str())
                    .unwrap_or(""),
            )
        });
        Some(Self {
            spec,
            map,
            patch_files,
        })
    }

    pub fn patch_is_unparseable(&self) -> bool {
        if self.spec.payload != FilePayloadKind::ApplyPatch {
            return false;
        }
        let command = self
            .map
            .get("command")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        crate::apply_patch_parser::looks_unparseable(
            command,
            self.patch_files.as_deref().unwrap_or_default(),
        )
    }

    pub fn paths(&self) -> Vec<String> {
        match self.spec.payload {
            FilePayloadKind::ApplyPatch => self
                .patch_files
                .as_deref()
                .unwrap_or_default()
                .iter()
                .flat_map(|file| file.affected_paths())
                .map(|path| path.display().to_string())
                .filter(|path| !path.is_empty())
                .collect(),
            FilePayloadKind::Notebook => self.single_path("notebook_path"),
            FilePayloadKind::ReadMany => self
                .map
                .get("paths")
                .and_then(|value| value.as_array())
                .into_iter()
                .flatten()
                .filter_map(|value| value.as_str())
                .filter(|path| !path.is_empty())
                .map(str::to_string)
                .collect(),
            FilePayloadKind::FilePath
            | FilePayloadKind::Content
            | FilePayloadKind::Replacement
            | FilePayloadKind::NormalizedContent => self.single_path("file_path"),
        }
    }

    pub fn content_pairs(&self) -> Vec<(String, String)> {
        let path = || {
            let key = if self.spec.payload == FilePayloadKind::Notebook {
                "notebook_path"
            } else {
                "file_path"
            };
            self.map
                .get(key)
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string()
        };
        match self.spec.payload {
            FilePayloadKind::ApplyPatch => self
                .patch_files
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter(|file| file.op != crate::apply_patch_parser::PatchOp::Delete)
                .filter_map(|file| {
                    let content = file.added_content();
                    if content.is_empty() {
                        return None;
                    }
                    let destination = file.move_to.as_ref().unwrap_or(&file.path);
                    Some((destination.display().to_string(), content))
                })
                .collect(),
            FilePayloadKind::Content | FilePayloadKind::NormalizedContent => self
                .map
                .get("content")
                .and_then(|value| value.as_str())
                .filter(|content| !content.is_empty())
                .map(|content| vec![(path(), content.to_string())])
                .unwrap_or_default(),
            FilePayloadKind::Replacement => {
                let mut pairs = Vec::new();
                if let Some(content) = self
                    .map
                    .get("new_string")
                    .and_then(|value| value.as_str())
                    .filter(|content| !content.is_empty())
                {
                    pairs.push((path(), content.to_string()));
                }
                if let Some(edits) = self.map.get("edits").and_then(|value| value.as_array()) {
                    for content in edits.iter().filter_map(|edit| {
                        edit.get("new_string")
                            .and_then(|value| value.as_str())
                            .filter(|content| !content.is_empty())
                    }) {
                        pairs.push((path(), content.to_string()));
                    }
                }
                pairs
            }
            FilePayloadKind::Notebook => {
                let deletes_cell =
                    self.map.get("edit_mode").and_then(|value| value.as_str()) == Some("delete");
                if deletes_cell {
                    return Vec::new();
                }
                self.map
                    .get("new_source")
                    .and_then(|value| value.as_str())
                    .filter(|content| !content.is_empty())
                    .map(|content| vec![(path(), content.to_string())])
                    .unwrap_or_default()
            }
            FilePayloadKind::FilePath | FilePayloadKind::ReadMany => Vec::new(),
        }
    }

    fn single_path(&self, key: &str) -> Vec<String> {
        self.map
            .get(key)
            .and_then(|value| value.as_str())
            .filter(|path| !path.is_empty())
            .map(|path| vec![path.to_string()])
            .unwrap_or_default()
    }
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

    #[test]
    fn canonical_single_file_readers_match_client_capabilities() {
        assert_eq!(read_tool_for_client(Client::Claude), Some("Read"));
        assert_eq!(read_tool_for_client(Client::Gemini), Some("read_file"));
        assert_eq!(read_tool_for_client(Client::Antigravity), Some("view_file"));
        assert_eq!(read_tool_for_client(Client::Codex), None);
    }

    #[test]
    fn parsed_patch_reuses_paths_content_and_malformed_state() {
        let patch = "*** Begin Patch\n*** Update File: src/old.rs\n*** Move to: src/new.rs\n@@\n-old\n+new\n*** End Patch";
        let map = serde_json::json!({"command": patch})
            .as_object()
            .unwrap()
            .clone();
        let parsed = ParsedFileInput::new("apply_patch", &map).unwrap();

        assert!(!parsed.patch_is_unparseable());
        assert_eq!(parsed.paths(), ["src/old.rs", "src/new.rs"]);
        assert_eq!(
            parsed.content_pairs(),
            [("src/new.rs".to_string(), "new".to_string())]
        );

        let bad = serde_json::json!({"command": "not a patch"})
            .as_object()
            .unwrap()
            .clone();
        let parsed = ParsedFileInput::new("apply_patch", &bad).unwrap();
        assert!(parsed.patch_is_unparseable());
        assert!(parsed.paths().is_empty());
        assert!(parsed.content_pairs().is_empty());
    }
}

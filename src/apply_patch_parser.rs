//! Parser for Codex's apply_patch unified-diff format.
//!
//! Codex sends file edits with `tool_name: "apply_patch"` and the entire
//! patch body in `tool_input.command`. There is no `file_path` field; paths
//! are inside the patch body. tool-gates needs these paths to run the same
//! file-guard checks Claude's Write/Edit get, and the added/modified content
//! to run Tier-1 secret detection.
//!
//! Format reference: `codex-rs/apply-patch/apply_patch_tool_instructions.md`.
//!
//! ```text
//! *** Begin Patch
//! *** Add File: <path>
//! +line1
//! +line2
//! *** Update File: <path>
//! *** Move to: <new_path>
//! @@
//! -old
//! +new
//! *** Delete File: <path>
//! *** End Patch
//! ```

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchOp {
    Add,
    Update,
    Delete,
}

#[derive(Debug, Clone)]
pub struct PatchedFile {
    pub op: PatchOp,
    pub path: PathBuf,
    /// Rename target for `*** Update File:` followed by `*** Move to:`. None
    /// otherwise.
    pub move_to: Option<PathBuf>,
    /// Lines this op writes to disk. For `Add`, every line in the section
    /// (each prefixed `+` is stripped). For `Update`, only `+`-prefixed
    /// lines (the new content). For `Delete`, empty.
    pub added_lines: Vec<String>,
}

impl PatchedFile {
    /// All paths this op writes to: the source path, plus the rename target
    /// when `Update` includes `*** Move to:`. file_guards must check both
    /// because a rename can land in a guarded directory.
    pub fn affected_paths(&self) -> Vec<&PathBuf> {
        let mut out = vec![&self.path];
        if let Some(ref dest) = self.move_to {
            out.push(dest);
        }
        out
    }

    /// Concatenate added lines for content scanning.
    pub fn added_content(&self) -> String {
        self.added_lines.join("\n")
    }
}

/// Parse a Codex apply_patch body. Mirrors Codex's lenient parser
/// (`codex-rs/apply-patch/src/parser.rs:266`) which calls
/// `lines[0].trim()` before matching markers, so a `\t*** Add File:` /
/// `  *** Update File:` header that Codex would apply does not bypass our
/// path extraction. Body lines (the `+`/`-`/context payload) are inspected on
/// the raw line so leading-whitespace inside file content is preserved.
///
/// `Move to:` is honored regardless of the surrounding op (Add/Update/Delete)
/// so a defensive rename target inside an Add or Delete block still surfaces
/// to file_guards. The Codex grammar declares Move-to only for Update, but
/// any leniency in the upstream applier would otherwise be a fail-open.
///
/// Returns the parsed files. Callers decide what to do with an empty result;
/// in practice tool-gates fails closed when the patch body is non-empty but
/// produced no files (see `handle_pre_tool_use_hook` for the apply_patch
/// branch). Malformed header lines (e.g. an `*** Add File:` with empty path)
/// still produce an entry so callers see the op rather than silently
/// dropping it.
pub fn parse_patch(body: &str) -> Vec<PatchedFile> {
    let mut files = Vec::new();
    let mut current: Option<PatchedFile> = None;

    for raw in body.lines() {
        let raw_no_cr = raw.trim_end_matches('\r');
        // Marker view: leading whitespace stripped to match Codex's parser.
        // Body view (raw_no_cr) preserves leading whitespace inside content.
        let marker = raw_no_cr.trim_start();

        if marker == "*** Begin Patch" {
            // Reset any in-progress section. Real patches start cleanly here.
            if let Some(f) = current.take() {
                files.push(f);
            }
            continue;
        }

        if marker == "*** End Patch" {
            if let Some(f) = current.take() {
                files.push(f);
            }
            continue;
        }

        if let Some(rest) = marker.strip_prefix("*** Add File: ") {
            if let Some(f) = current.take() {
                files.push(f);
            }
            current = Some(PatchedFile {
                op: PatchOp::Add,
                path: PathBuf::from(rest.trim()),
                move_to: None,
                added_lines: Vec::new(),
            });
            continue;
        }

        if let Some(rest) = marker.strip_prefix("*** Update File: ") {
            if let Some(f) = current.take() {
                files.push(f);
            }
            current = Some(PatchedFile {
                op: PatchOp::Update,
                path: PathBuf::from(rest.trim()),
                move_to: None,
                added_lines: Vec::new(),
            });
            continue;
        }

        if let Some(rest) = marker.strip_prefix("*** Delete File: ") {
            if let Some(f) = current.take() {
                files.push(f);
            }
            current = Some(PatchedFile {
                op: PatchOp::Delete,
                path: PathBuf::from(rest.trim()),
                move_to: None,
                added_lines: Vec::new(),
            });
            continue;
        }

        if let Some(rest) = marker.strip_prefix("*** Move to: ") {
            if let Some(f) = current.as_mut() {
                // Defensive: honor Move-to regardless of f.op. The grammar
                // only allows it under Update, but if Codex's lenient parser
                // ever extends to Add/Delete, the rename target still flows
                // through file_guards via affected_paths().
                f.move_to = Some(PathBuf::from(rest.trim()));
            }
            continue;
        }

        // Body lines.
        if let Some(f) = current.as_mut() {
            match f.op {
                PatchOp::Add => {
                    // Every body line is part of the new file. The grammar
                    // guarantees a `+` prefix on each line, but tolerate
                    // unprefixed too so a slightly malformed Add still sees
                    // its content scanned for secrets.
                    if let Some(content) = raw_no_cr.strip_prefix('+') {
                        f.added_lines.push(content.to_string());
                    } else if !marker.starts_with("@@") && !marker.is_empty() {
                        f.added_lines.push(raw_no_cr.to_string());
                    }
                }
                PatchOp::Update => {
                    // Only `+` lines write new content. `-` removes,
                    // ` ` (space) is context, `@@` is a hunk separator.
                    if let Some(content) = raw_no_cr.strip_prefix('+') {
                        f.added_lines.push(content.to_string());
                    }
                }
                PatchOp::Delete => {
                    // Delete has no body. Ignore anything that bleeds in.
                }
            }
        }
    }

    if let Some(f) = current {
        files.push(f);
    }

    files
}

/// True when `body` looks non-trivial (non-empty after trim) but `parsed`
/// extracted nothing. Callers should treat this as a parse failure and fail
/// closed, since Codex's lenient parser may apply a body tool-gates can't
/// route through file_guards. See `handle_pre_tool_use_hook` apply_patch
/// branch for the deny site.
pub fn looks_unparseable(body: &str, parsed: &[PatchedFile]) -> bool {
    !body.trim().is_empty() && parsed.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_add() {
        let body = "*** Begin Patch\n\
                    *** Add File: hello.txt\n\
                    +hello\n\
                    +world\n\
                    *** End Patch\n";
        let files = parse_patch(body);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].op, PatchOp::Add);
        assert_eq!(files[0].path, PathBuf::from("hello.txt"));
        assert_eq!(files[0].added_lines, vec!["hello", "world"]);
        assert_eq!(files[0].added_content(), "hello\nworld");
    }

    #[test]
    fn parses_single_update() {
        let body = "*** Begin Patch\n\
                    *** Update File: src/app.py\n\
                    @@\n\
                    -old line\n\
                    +new line\n\
                     context\n\
                    *** End Patch\n";
        let files = parse_patch(body);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].op, PatchOp::Update);
        assert_eq!(files[0].path, PathBuf::from("src/app.py"));
        assert_eq!(files[0].added_lines, vec!["new line"]);
    }

    #[test]
    fn parses_single_delete() {
        let body = "*** Begin Patch\n\
                    *** Delete File: tmp/old.txt\n\
                    *** End Patch\n";
        let files = parse_patch(body);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].op, PatchOp::Delete);
        assert_eq!(files[0].path, PathBuf::from("tmp/old.txt"));
        assert!(files[0].added_lines.is_empty());
    }

    #[test]
    fn parses_update_with_move() {
        let body = "*** Begin Patch\n\
                    *** Update File: old/name.txt\n\
                    *** Move to: new/name.txt\n\
                    @@\n\
                    -from\n\
                    +new\n\
                    *** End Patch\n";
        let files = parse_patch(body);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].op, PatchOp::Update);
        assert_eq!(files[0].path, PathBuf::from("old/name.txt"));
        assert_eq!(files[0].move_to, Some(PathBuf::from("new/name.txt")));
        let paths: Vec<&PathBuf> = files[0].affected_paths();
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn parses_multi_file_mixed_ops() {
        let body = "*** Begin Patch\n\
                    *** Add File: new.txt\n\
                    +greeting\n\
                    *** Update File: existing.txt\n\
                    @@\n\
                    -old\n\
                    +new\n\
                    *** Delete File: gone.txt\n\
                    *** End Patch\n";
        let files = parse_patch(body);
        assert_eq!(files.len(), 3);
        assert_eq!(files[0].op, PatchOp::Add);
        assert_eq!(files[0].path, PathBuf::from("new.txt"));
        assert_eq!(files[1].op, PatchOp::Update);
        assert_eq!(files[1].path, PathBuf::from("existing.txt"));
        assert_eq!(files[2].op, PatchOp::Delete);
        assert_eq!(files[2].path, PathBuf::from("gone.txt"));
    }

    #[test]
    fn tolerates_missing_begin_end_markers() {
        let body = "*** Add File: hello.txt\n\
                    +hi\n";
        let files = parse_patch(body);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, PathBuf::from("hello.txt"));
        assert_eq!(files[0].added_lines, vec!["hi"]);
    }

    #[test]
    fn move_to_honored_in_any_op_for_defense_in_depth() {
        // The Codex grammar declares Move-to under Update only, but the
        // upstream parser is lenient. tool-gates honors Move-to in any op
        // so the rename target always reaches file_guards. Without this,
        // a body like `*** Add File: safe.txt / *** Move to: ~/.claude/...`
        // would skip path-checking the rename destination.
        let body = "*** Begin Patch\n\
                    *** Add File: new.txt\n\
                    *** Move to: somewhere.txt\n\
                    +data\n\
                    *** End Patch\n";
        let files = parse_patch(body);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].move_to, Some(PathBuf::from("somewhere.txt")));
        // affected_paths must include both source and rename target.
        let paths: Vec<&PathBuf> = files[0].affected_paths();
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn empty_input_yields_no_files() {
        assert!(parse_patch("").is_empty());
        assert!(parse_patch("*** Begin Patch\n*** End Patch\n").is_empty());
    }

    #[test]
    fn whitespace_padded_headers_still_parse() {
        // Codex's parser at codex-rs/apply-patch/src/parser.rs:266 trims each
        // hunk header before strip_prefix. tool-gates must match or the
        // whitespace-padded variant becomes a fail-open bypass of file_guards
        // and the Tier-1 secret scanner.
        let body = "*** Begin Patch\n\
                    \t*** Add File: secrets.env\n\
                    +API_KEY=fake-AKIATESTKEYHERE\n\
                      *** Update File: src/app.py\n\
                    @@\n\
                    +new line\n\
                    *** End Patch\n";
        let files = parse_patch(body);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].op, PatchOp::Add);
        assert_eq!(files[0].path, PathBuf::from("secrets.env"));
        assert_eq!(files[1].op, PatchOp::Update);
        assert_eq!(files[1].path, PathBuf::from("src/app.py"));
    }

    #[test]
    fn whitespace_padded_begin_end_markers_still_parse() {
        let body = "  *** Begin Patch\n\
                    *** Add File: a.txt\n\
                    +x\n\
                    \t*** End Patch\n";
        let files = parse_patch(body);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, PathBuf::from("a.txt"));
    }

    #[test]
    fn looks_unparseable_flags_non_empty_body_with_no_files() {
        // No headers at all -- the broadest fail-open vector. Callers must
        // route this to deny.
        let body = "+let key = \"AKIATESTKEYHERE\";\n+other\n";
        let parsed = parse_patch(body);
        assert!(parsed.is_empty());
        assert!(looks_unparseable(body, &parsed));
    }

    #[test]
    fn looks_unparseable_false_for_empty_body() {
        assert!(!looks_unparseable("", &[]));
        assert!(!looks_unparseable("   \n\t\n", &[]));
    }

    #[test]
    fn looks_unparseable_false_when_files_extracted() {
        let body = "*** Begin Patch\n*** Add File: foo\n+x\n*** End Patch\n";
        let parsed = parse_patch(body);
        assert!(!parsed.is_empty());
        assert!(!looks_unparseable(body, &parsed));
    }

    #[test]
    fn malformed_header_still_emits_entry_for_path() {
        // An `*** Add File:` with empty path is malformed but still tells
        // file_guards "this op happened"; downstream callers handle empties.
        let body = "*** Begin Patch\n\
                    *** Add File: \n\
                    +data\n\
                    *** End Patch\n";
        let files = parse_patch(body);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, PathBuf::from(""));
    }

    #[test]
    fn handles_crlf_line_endings() {
        let body = "*** Begin Patch\r\n\
                    *** Add File: foo.txt\r\n\
                    +line1\r\n\
                    *** End Patch\r\n";
        let files = parse_patch(body);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, PathBuf::from("foo.txt"));
        assert_eq!(files[0].added_lines, vec!["line1"]);
    }

    #[test]
    fn affected_paths_for_simple_op() {
        let body = "*** Begin Patch\n\
                    *** Update File: foo.txt\n\
                    @@\n\
                    +x\n\
                    *** End Patch\n";
        let files = parse_patch(body);
        let paths = files[0].affected_paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], &PathBuf::from("foo.txt"));
    }
}

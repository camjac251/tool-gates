//! Filesystem path resolution shared by the scratch and accept-edits policies.

pub(crate) fn resolve_path(path: &str) -> String {
    use std::path::Path;

    let path_obj = Path::new(path);

    // Whole path exists: canonicalize resolves all symlinks, `.`, and `..`.
    if let Ok(canonical) = std::fs::canonicalize(path_obj) {
        return canonical.to_string_lossy().to_string();
    }

    // The path does not fully exist yet (the common case for a write that
    // creates files/dirs). Canonicalize the LONGEST existing ancestor, which
    // resolves any symlink anywhere in that real prefix, then re-attach the
    // remaining not-yet-existing components and collapse them lexically.
    //
    // The old behavior canonicalized only the immediate parent, which missed a
    // symlink followed by >=2 missing segments (the `mkdir -p` /
    // Write-creates-parents shape): both the full path and its immediate parent
    // fail to exist, so the symlink stayed an unresolved literal and a write
    // could escape the scratch base undetected. Walking to the longest existing
    // ancestor closes that gap. The stripped tail components do not exist on
    // disk, so none of them is a symlink, which makes the `..` collapse in
    // `resolve_path_manual` safe (no symlink can sit before a `..`).
    for ancestor in path_obj.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        if let Ok(canonical_ancestor) = std::fs::canonicalize(ancestor) {
            return match path_obj.strip_prefix(ancestor) {
                Ok(tail) => {
                    let joined = canonical_ancestor.join(tail);
                    resolve_path_manual(&joined.to_string_lossy())
                }
                Err(_) => canonical_ancestor.to_string_lossy().to_string(),
            };
        }
    }

    // No ancestor exists (e.g. a relative path with no real prefix): fall back
    // to pure lexical resolution (handles `.` and `..` but not symlinks).
    resolve_path_manual(path)
}

/// Manual path resolution that handles `.` and `..` components but not symlinks.
/// Used as fallback when filesystem-based canonicalization fails.
fn resolve_path_manual(path: &str) -> String {
    use std::path::Path;

    let path = Path::new(path);
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => components.push("/".to_string()),
            std::path::Component::Normal(s) => {
                if let Some(s) = s.to_str() {
                    components.push(s.to_string());
                }
            }
            std::path::Component::ParentDir => {
                if components.len() > 1 {
                    components.pop();
                }
            }
            std::path::Component::CurDir => {}
            std::path::Component::Prefix(_) => {}
        }
    }
    if components.len() == 1 {
        "/".to_string()
    } else {
        components.join("/").replacen("//", "/", 1)
    }
}

/// Check if a path is under any of the allowed directories.
pub(crate) fn is_under_any_dir(path: &str, allowed_dirs: &[String]) -> bool {
    let path_normalized = path.trim_end_matches('/');
    for dir in allowed_dirs {
        // Must either equal the dir exactly OR start with dir/
        if path_normalized == dir || path_normalized.starts_with(&format!("{}/", dir)) {
            return true;
        }
    }
    false
}

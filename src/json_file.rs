//! Transactional JSON-file updates for user settings and hook configuration.

use fs2::FileExt;
use serde_json::Value;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tempfile::Builder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyPolicy {
    Reject,
    EmptyObject,
}

#[derive(Debug)]
pub struct JsonWriteResult<R> {
    pub result: R,
    pub changed: bool,
    pub backup_path: Option<PathBuf>,
}

pub fn read_json(path: &Path, empty_policy: EmptyPolicy) -> io::Result<Value> {
    let target = effective_target(path)?;
    let (existed, bytes, _) = read_snapshot(&target)?;
    parse_snapshot(&target, existed, &bytes, empty_policy)
}

pub fn update_json<R>(
    path: &Path,
    empty_policy: EmptyPolicy,
    backup_existing: bool,
    mutate: impl FnOnce(&mut Value) -> io::Result<R>,
) -> io::Result<JsonWriteResult<R>> {
    update_json_with_hook(path, empty_policy, backup_existing, mutate, || Ok(()))
}

fn update_json_with_hook<R>(
    path: &Path,
    empty_policy: EmptyPolicy,
    backup_existing: bool,
    mutate: impl FnOnce(&mut Value) -> io::Result<R>,
    before_compare: impl FnOnce() -> io::Result<()>,
) -> io::Result<JsonWriteResult<R>> {
    let target = effective_target(path)?;
    let parent = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let lock_path = sidecar_path(&target, ".tool-gates.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    #[allow(clippy::incompatible_msrv)]
    lock.lock_exclusive()?;

    let (existed, original, permissions) = read_snapshot(&target)?;
    let mut value = parse_snapshot(&target, existed, &original, empty_policy)?;
    let original_value = value.clone();
    let result = mutate(&mut value)?;

    if value == original_value {
        #[allow(clippy::incompatible_msrv)]
        lock.unlock()?;
        return Ok(JsonWriteResult {
            result,
            changed: false,
            backup_path: None,
        });
    }

    let intended = serialize_verified(&value)?;
    let mut temp = Builder::new()
        .prefix(".tool-gates-write-")
        .tempfile_in(parent)?;
    apply_permissions(temp.as_file(), permissions.as_ref())?;
    temp.write_all(&intended)?;
    temp.flush()?;
    temp.as_file().sync_all()?;

    before_compare()?;
    ensure_unchanged(&target, existed, &original)?;

    let backup_path = if backup_existing && existed {
        Some(write_backup(
            &target,
            parent,
            &original,
            permissions.as_ref(),
        )?)
    } else {
        None
    };
    if backup_path.is_some() {
        sync_parent(parent)?;
    }

    temp.persist(&target).map_err(|error| error.error)?;
    sync_parent(parent)?;
    verify_committed(&target, &value)?;

    #[allow(clippy::incompatible_msrv)]
    lock.unlock()?;
    Ok(JsonWriteResult {
        result,
        changed: true,
        backup_path,
    })
}

fn effective_target(path: &Path) -> io::Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => fs::canonicalize(path),
        Ok(_) => Ok(path.to_path_buf()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(error) => Err(error),
    }
}

fn sidecar_path(target: &Path, suffix: &str) -> PathBuf {
    let mut name = target
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("settings.json"));
    name.push(suffix);
    target.with_file_name(name)
}

fn read_snapshot(target: &Path) -> io::Result<(bool, Vec<u8>, Option<Permissions>)> {
    match fs::read(target) {
        Ok(bytes) => {
            let permissions = fs::metadata(target)?.permissions();
            Ok((true, bytes, Some(permissions)))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok((false, Vec::new(), None)),
        Err(error) => Err(error),
    }
}

fn parse_snapshot(
    target: &Path,
    existed: bool,
    bytes: &[u8],
    empty_policy: EmptyPolicy,
) -> io::Result<Value> {
    if !existed || (bytes.is_empty() && empty_policy == EmptyPolicy::EmptyObject) {
        return Ok(serde_json::json!({}));
    }
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is empty", target.display()),
        ));
    }
    serde_json::from_slice(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not valid JSON: {error}", target.display()),
        )
    })
}

fn serialize_verified(value: &Value) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let reparsed: Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if reparsed != *value {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "serialized JSON did not round-trip",
        ));
    }
    Ok(bytes)
}

fn apply_permissions(file: &File, permissions: Option<&Permissions>) -> io::Result<()> {
    if let Some(permissions) = permissions {
        file.set_permissions(permissions.clone())?;
    }
    Ok(())
}

fn ensure_unchanged(target: &Path, existed: bool, original: &[u8]) -> io::Result<()> {
    match fs::read(target) {
        Ok(current) if existed && current == original => Ok(()),
        Err(error) if !existed && error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("{} changed during update", target.display()),
        )),
    }
}

fn write_backup(
    target: &Path,
    parent: &Path,
    original: &[u8],
    permissions: Option<&Permissions>,
) -> io::Result<PathBuf> {
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("settings.json");
    let mut backup = Builder::new()
        .prefix(&format!("{file_name}.backup-"))
        .tempfile_in(parent)?;
    apply_permissions(backup.as_file(), permissions)?;
    backup.write_all(original)?;
    backup.flush()?;
    backup.as_file().sync_all()?;
    backup
        .keep()
        .map(|(_, path)| path)
        .map_err(|error| error.error)
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> io::Result<()> {
    Ok(())
}

fn verify_committed(target: &Path, intended: &Value) -> io::Result<()> {
    let bytes = fs::read(target)?;
    let committed: Value = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} failed post-write validation: {error}", target.display()),
        )
    })?;
    if committed != *intended {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} changed after atomic replacement", target.display()),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn update_merges_backs_up_and_preserves_unrelated_json() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("settings.json");
        let original = br#"{"unrelated":{"enabled":true}}"#;
        fs::write(&path, original).expect("seed settings");

        let outcome = update_json(&path, EmptyPolicy::Reject, true, |value| {
            value["permissions"] = json!({"allow":["Bash(mytool status:*)"]});
            Ok("updated")
        })
        .expect("update settings");

        assert_eq!(outcome.result, "updated");
        assert!(outcome.changed);
        let backup = outcome.backup_path.expect("backup path");
        assert_eq!(fs::read(backup).expect("read backup"), original);
        let committed: Value =
            serde_json::from_slice(&fs::read(path).expect("read committed")).expect("valid json");
        assert_eq!(committed["unrelated"]["enabled"], true);
        assert_eq!(
            committed["permissions"]["allow"][0],
            "Bash(mytool status:*)"
        );
    }

    #[test]
    fn invalid_json_and_mutation_errors_preserve_original_bytes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let invalid = temp.path().join("invalid.json");
        fs::write(&invalid, b"{broken").expect("seed invalid json");
        assert!(update_json(&invalid, EmptyPolicy::Reject, true, |_| Ok(())).is_err());
        assert_eq!(fs::read(&invalid).expect("read invalid"), b"{broken");

        let valid = temp.path().join("valid.json");
        let original = b"{\"key\":1}\n";
        fs::write(&valid, original).expect("seed valid json");
        let result = update_json(&valid, EmptyPolicy::Reject, true, |value| {
            value["key"] = json!(2);
            Err::<(), _>(io::Error::other("mutation failed"))
        });
        assert!(result.is_err());
        assert_eq!(fs::read(valid).expect("read valid"), original);
    }

    #[test]
    fn no_change_does_not_rewrite_or_create_backup() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("settings.json");
        let original = b"{\"key\":1}\n";
        fs::write(&path, original).expect("seed settings");

        let outcome =
            update_json(&path, EmptyPolicy::Reject, true, |_| Ok(7)).expect("no-op update");
        assert_eq!(outcome.result, 7);
        assert!(!outcome.changed);
        assert!(outcome.backup_path.is_none());
        assert_eq!(fs::read(path).expect("read settings"), original);
    }

    #[test]
    fn empty_policy_and_missing_target_are_explicit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let empty = temp.path().join("empty.json");
        fs::write(&empty, []).expect("seed empty file");
        assert!(update_json(&empty, EmptyPolicy::Reject, false, |_| Ok(())).is_err());

        update_json(&empty, EmptyPolicy::EmptyObject, false, |value| {
            value["created"] = json!(true);
            Ok(())
        })
        .expect("update empty file");

        let missing = temp.path().join("nested/new.json");
        update_json(&missing, EmptyPolicy::Reject, false, |value| {
            value["created"] = json!(true);
            Ok(())
        })
        .expect("create missing file");
        assert!(missing.exists());
    }

    #[cfg(unix)]
    #[test]
    fn replacement_preserves_permissions_and_follows_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target.json");
        let link = temp.path().join("settings.json");
        fs::write(&target, b"{\"key\":1}\n").expect("seed target");
        fs::set_permissions(&target, Permissions::from_mode(0o640)).expect("set mode");
        symlink(&target, &link).expect("create symlink");

        update_json(&link, EmptyPolicy::Reject, true, |value| {
            value["key"] = json!(2);
            Ok(())
        })
        .expect("update through symlink");

        assert!(
            fs::symlink_metadata(&link)
                .expect("link metadata")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        let committed: Value = serde_json::from_slice(&fs::read(target).expect("read target"))
            .expect("valid target json");
        assert_eq!(committed["key"], 2);
    }

    #[test]
    fn concurrent_updates_share_the_sidecar_lock() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("settings.json");
        fs::write(&path, b"{}\n").expect("seed settings");

        let threads = (0..12)
            .map(|index| {
                let path = path.clone();
                std::thread::spawn(move || {
                    update_json(&path, EmptyPolicy::Reject, false, |value| {
                        value[format!("key-{index}")] = json!(index);
                        Ok(())
                    })
                    .expect("concurrent update");
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().expect("join update thread");
        }

        let committed: Value = serde_json::from_slice(&fs::read(path).expect("read settings"))
            .expect("valid settings");
        for index in 0..12 {
            assert_eq!(committed[format!("key-{index}")], index);
        }
    }

    #[test]
    fn external_change_aborts_before_replacement() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("settings.json");
        fs::write(&path, b"{\"key\":1}\n").expect("seed settings");

        let result = update_json_with_hook(
            &path,
            EmptyPolicy::Reject,
            true,
            |value| {
                value["key"] = json!(2);
                Ok(())
            },
            || {
                fs::write(&path, b"{\"external\":true}\n")?;
                Ok(())
            },
        );

        assert_eq!(
            result.expect_err("conflict must abort").kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            fs::read(path).expect("read external update"),
            b"{\"external\":true}\n"
        );
    }
}

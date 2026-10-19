use super::files::with;
use std::path::PathBuf;

/// Every path changed since the last call, with its bytes now, or none where it was removed.
pub fn take_changes() -> Vec<(PathBuf, Option<Vec<u8>>)> {
    with(|files| {
        let changed = core::mem::take(&mut files.changed);
        Ok(changed
            .into_iter()
            .map(|path| {
                let bytes = files.bytes.get(&path).cloned();
                (path, bytes)
            })
            .collect())
    })
    .unwrap_or_default()
}

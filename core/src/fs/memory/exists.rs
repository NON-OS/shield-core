use super::files::with;
use std::path::Path;

pub fn exists(path: &Path) -> bool {
    with(|files| {
        Ok(files.bytes.contains_key(path) || files.bytes.keys().any(|k| k.starts_with(path)))
    })
    .unwrap_or(false)
}

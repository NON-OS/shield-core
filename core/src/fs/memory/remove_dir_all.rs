use super::files::with;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

/// Remove every file under `path`. Like std, a directory with nothing in it is not found.
pub fn remove_dir_all(path: impl AsRef<Path>) -> Result<()> {
    with(|files| {
        let under: Vec<_> =
            files.bytes.keys().filter(|k| k.starts_with(path.as_ref())).cloned().collect();
        if under.is_empty() {
            return Err(Error::from(ErrorKind::NotFound));
        }
        for key in &under {
            files.drop_file(key);
        }
        Ok(())
    })
}

use super::files::with;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

/// Move a file over another in one step, as the native rename does, so a reader never sees half.
pub fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    with(|files| {
        let from = from.as_ref().to_path_buf();
        let bytes = files.bytes.remove(&from).ok_or_else(|| Error::from(ErrorKind::NotFound))?;
        files.changed.insert(from);
        files.put(to.as_ref().to_path_buf(), bytes);
        Ok(())
    })
}

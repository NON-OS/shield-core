use super::files::with;
use std::path::PathBuf;

/// Put back a file the page stored earlier. Loading is not a change, so it is not saved again.
pub fn load(path: PathBuf, bytes: Vec<u8>) {
    let _ = with(|files| {
        files.bytes.insert(path, bytes);
        Ok(())
    });
}

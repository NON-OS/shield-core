use std::ffi::OsString;
use std::path::PathBuf;

/// A file directly inside a directory being listed.
pub struct DirEntry {
    pub(super) path: PathBuf,
}

impl DirEntry {
    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    pub fn file_name(&self) -> OsString {
        self.path.file_name().map(OsString::from).unwrap_or_default()
    }
}

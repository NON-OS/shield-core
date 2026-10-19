use super::files::with;
use super::DirEntry;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

/// The files directly inside `path`, in name order.
pub struct ReadDir {
    entries: std::vec::IntoIter<DirEntry>,
}

impl Iterator for ReadDir {
    type Item = Result<DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next().map(Ok)
    }
}

pub fn read_dir(path: impl AsRef<Path>) -> Result<ReadDir> {
    with(|files| {
        let dir = path.as_ref();
        let entries: Vec<DirEntry> = files
            .bytes
            .keys()
            .filter(|k| k.parent() == Some(dir))
            .map(|k| DirEntry { path: k.clone() })
            .collect();
        if entries.is_empty() {
            return Err(Error::from(ErrorKind::NotFound));
        }
        Ok(ReadDir { entries: entries.into_iter() })
    })
}

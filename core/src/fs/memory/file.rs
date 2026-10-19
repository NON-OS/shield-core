use super::files::with;
use std::io::{Error, ErrorKind, Result, Write};
use std::path::PathBuf;

/// A file opened to append to. Each write lands in the store at once, so syncing has nothing left
/// to do and a crash can lose only what the page had not saved yet.
pub struct File {
    pub(super) path: PathBuf,
}

impl File {
    pub fn sync_data(&self) -> Result<()> {
        Ok(())
    }
}

impl Write for File {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        with(|files| {
            let bytes =
                files.bytes.get_mut(&self.path).ok_or_else(|| Error::from(ErrorKind::NotFound))?;
            bytes.extend_from_slice(buf);
            files.changed.insert(self.path.clone());
            Ok(buf.len())
        })
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

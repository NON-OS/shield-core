use super::files::with;
use std::io::Result;
use std::path::Path;

pub fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<()> {
    with(|files| {
        files.put(path.as_ref().to_path_buf(), contents.as_ref().to_vec());
        Ok(())
    })
}

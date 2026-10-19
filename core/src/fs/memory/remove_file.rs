use super::files::with;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

pub fn remove_file(path: impl AsRef<Path>) -> Result<()> {
    with(|files| {
        if files.drop_file(&path.as_ref().to_path_buf()) {
            Ok(())
        } else {
            Err(Error::from(ErrorKind::NotFound))
        }
    })
}

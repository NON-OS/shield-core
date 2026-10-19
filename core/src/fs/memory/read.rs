use super::files::with;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

pub fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    with(|files| {
        files.bytes.get(path.as_ref()).cloned().ok_or_else(|| Error::from(ErrorKind::NotFound))
    })
}

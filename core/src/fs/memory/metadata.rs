use super::files::with;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

/// The one fact the wallet asks of a file: how long it is.
pub struct Metadata {
    len: u64,
}

impl Metadata {
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

pub fn metadata(path: impl AsRef<Path>) -> Result<Metadata> {
    with(|files| {
        let bytes =
            files.bytes.get(path.as_ref()).ok_or_else(|| Error::from(ErrorKind::NotFound))?;
        Ok(Metadata { len: u64::try_from(bytes.len()).unwrap_or(u64::MAX) })
    })
}

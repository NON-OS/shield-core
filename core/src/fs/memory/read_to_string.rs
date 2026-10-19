use std::io::{Error, ErrorKind, Result};
use std::path::Path;

pub fn read_to_string(path: impl AsRef<Path>) -> Result<String> {
    String::from_utf8(super::read(path)?).map_err(|_| Error::from(ErrorKind::InvalidData))
}

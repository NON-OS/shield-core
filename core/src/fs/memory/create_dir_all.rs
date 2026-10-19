use std::io::Result;
use std::path::Path;

/// Directories exist as soon as a file is put in them, so there is nothing to make.
pub fn create_dir_all(_path: impl AsRef<Path>) -> Result<()> {
    Ok(())
}

use super::files::with;
use super::File;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

/// The two options the note log opens with: create it if missing, and append to it.
#[derive(Default)]
pub struct OpenOptions {
    create: bool,
    append: bool,
}

impl OpenOptions {
    pub fn new() -> OpenOptions {
        OpenOptions::default()
    }

    pub fn create(&mut self, create: bool) -> &mut OpenOptions {
        self.create = create;
        self
    }

    pub fn append(&mut self, append: bool) -> &mut OpenOptions {
        self.append = append;
        self
    }

    pub fn open(&self, path: impl AsRef<Path>) -> Result<File> {
        if !self.append {
            return Err(Error::from(ErrorKind::Unsupported));
        }
        let path = path.as_ref().to_path_buf();
        with(|files| {
            if !files.bytes.contains_key(&path) {
                if !self.create {
                    return Err(Error::from(ErrorKind::NotFound));
                }
                files.put(path.clone(), Vec::new());
            }
            Ok(())
        })?;
        Ok(File { path })
    }
}

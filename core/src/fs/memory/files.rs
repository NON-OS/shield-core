//! The one store every call shares, and the paths changed since the page last saved.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;
use std::sync::Mutex;
use zeroize::Zeroize;

#[derive(Default)]
pub(super) struct Files {
    pub(super) bytes: BTreeMap<PathBuf, Vec<u8>>,
    pub(super) changed: BTreeSet<PathBuf>,
}

impl Files {
    pub(super) fn put(&mut self, path: PathBuf, bytes: Vec<u8>) {
        if let Some(mut old) = self.bytes.insert(path.clone(), bytes) {
            old.zeroize();
        }
        self.changed.insert(path);
    }

    pub(super) fn drop_file(&mut self, path: &PathBuf) -> bool {
        let Some(mut old) = self.bytes.remove(path) else { return false };
        old.zeroize();
        self.changed.insert(path.clone());
        true
    }
}

static FILES: Mutex<Files> = Mutex::new(Files { bytes: BTreeMap::new(), changed: BTreeSet::new() });

/// Run `work` on the store. A lock poisoned by a panic elsewhere is reported as an I/O error.
pub(super) fn with<T>(work: impl FnOnce(&mut Files) -> Result<T>) -> Result<T> {
    let mut files = FILES.lock().map_err(|_| Error::from(ErrorKind::Other))?;
    work(&mut files)
}

use std::path::Path;

/// Whether a file is there. `Path::exists` asks std's file system, which a browser does not have.
#[cfg(not(target_arch = "wasm32"))]
#[inline]
pub fn exists(path: &Path) -> bool {
    path.exists()
}

#[cfg(target_arch = "wasm32")]
pub fn exists(path: &Path) -> bool {
    super::memory::exists(path)
}

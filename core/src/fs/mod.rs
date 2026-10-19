//! The files the wallet keeps. Natively these are std's own functions, so a native build calls
//! exactly what it called before this module existed. A browser has no file system, so there they
//! are files held in memory, which the page loads from storage before the wallet opens and saves
//! after every change.

mod exists;
#[cfg(target_arch = "wasm32")]
pub mod memory;

pub use exists::exists;
#[cfg(target_arch = "wasm32")]
pub use memory::{
    create_dir_all, metadata, read, read_dir, read_to_string, remove_dir_all, remove_file, rename,
    write, OpenOptions,
};
#[cfg(not(target_arch = "wasm32"))]
pub use std::fs::{
    create_dir_all, metadata, read, read_dir, read_to_string, remove_dir_all, remove_file, rename,
    write, OpenOptions,
};

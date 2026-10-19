//! Files held in memory, for the browser build. The page loads what it stored before the wallet
//! opens, with `load`, and after each call saves what `take_changes` returns, so storage holds the
//! same bytes a phone keeps on disk. Directories are implied by the paths of the files in them.

mod changes;
mod create_dir_all;
mod dir_entry;
mod exists;
mod file;
mod files;
mod load;
mod metadata;
mod open_options;
mod read;
mod read_dir;
mod read_to_string;
mod remove_dir_all;
mod remove_file;
mod rename;
mod write;

pub use changes::take_changes;
pub use create_dir_all::create_dir_all;
pub use dir_entry::DirEntry;
pub(super) use exists::exists;
pub use file::File;
pub use load::load;
pub use metadata::{metadata, Metadata};
pub use open_options::OpenOptions;
pub use read::read;
pub use read_dir::{read_dir, ReadDir};
pub use read_to_string::read_to_string;
pub use remove_dir_all::remove_dir_all;
pub use remove_file::remove_file;
pub use rename::rename;
pub use write::write;

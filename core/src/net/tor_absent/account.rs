//! Without circuits there is nothing to keep apart per account, so the work just runs.

pub fn as_account<T>(_index: u32, work: impl FnOnce() -> T) -> T {
    work()
}

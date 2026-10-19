//! A browser has one path for every account, so there are no circuits to keep apart.

pub fn as_account<T>(_index: u32, work: impl FnOnce() -> T) -> T {
    work()
}

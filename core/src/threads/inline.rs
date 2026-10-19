use std::marker::PhantomData;

/// Where closures are spawned, as std's `Scope`.
pub struct Scope<'scope, 'env: 'scope> {
    scope: PhantomData<&'scope mut &'scope ()>,
    env: PhantomData<&'env mut &'env ()>,
}

/// A finished closure's result, as std's `ScopedJoinHandle`.
pub struct Joined<T> {
    out: T,
}

impl<T> Joined<T> {
    /// Never an error: a panic in the closure aborts, as every panic in this build does.
    pub fn join(self) -> std::thread::Result<T> {
        Ok(self.out)
    }
}

impl<'scope, 'env> Scope<'scope, 'env> {
    pub fn spawn<F, T>(&'scope self, work: F) -> Joined<T>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        Joined { out: work() }
    }
}

pub fn scope<'env, F, T>(work: F) -> T
where
    F: for<'scope> FnOnce(&'scope Scope<'scope, 'env>) -> T,
{
    work(&Scope { scope: PhantomData, env: PhantomData })
}

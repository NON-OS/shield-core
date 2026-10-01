// NONOS Operating System (AGPL-3.0-or-later)

//! One dispatch point for the prover's data-parallel maps. With the `parallel`
//! feature the maps run across every core; without it they are the ordinary
//! serial iterators the kernel builds. Both forms are indexed and
//! order-preserving, so the output is identical either way: the callers pass
//! pure functions of the index or element, and a bit-exact gate proves the two
//! prover forms emit the same proof bytes.

use alloc::vec::Vec;

/// Map a pure function over `0..n`, collecting in index order.
#[cfg(feature = "parallel")]
pub fn map_index<T, F>(n: usize, f: F) -> Vec<T>
where
    T: Send,
    F: Fn(usize) -> T + Send + Sync,
{
    use rayon::prelude::*;
    (0..n).into_par_iter().map(f).collect()
}

#[cfg(not(feature = "parallel"))]
pub fn map_index<T, F>(n: usize, f: F) -> Vec<T>
where
    F: Fn(usize) -> T,
{
    (0..n).map(f).collect()
}

/// Map a pure function over a slice, collecting in element order.
#[cfg(feature = "parallel")]
pub fn map_slice<A, T, F>(items: &[A], f: F) -> Vec<T>
where
    A: Sync,
    T: Send,
    F: Fn(&A) -> T + Send + Sync,
{
    use rayon::prelude::*;
    items.par_iter().map(f).collect()
}

#[cfg(not(feature = "parallel"))]
pub fn map_slice<A, T, F>(items: &[A], f: F) -> Vec<T>
where
    F: Fn(&A) -> T,
{
    items.iter().map(f).collect()
}

/// Apply a mutation to each `size`-long chunk of a slice, the chunks disjoint. With
/// the `parallel` feature the chunks run across every core; without it they run in
/// order. No two chunks share an element, so the result is the same either way,
/// which is what lets the transform's butterflies, which touch one block at a
/// time, go wide without changing a bit of the proof.
#[cfg(feature = "parallel")]
pub fn for_each_chunk_mut<T, F>(items: &mut [T], size: usize, f: F)
where
    T: Send,
    F: Fn(&mut [T]) + Send + Sync,
{
    use rayon::prelude::*;
    items.par_chunks_mut(size).for_each(f);
}

#[cfg(not(feature = "parallel"))]
pub fn for_each_chunk_mut<T, F>(items: &mut [T], size: usize, f: F)
where
    F: Fn(&mut [T]),
{
    items.chunks_mut(size).for_each(f);
}

/// `for_each_chunk_mut` with each chunk told where it starts, so a task that
/// mutates its chunk can also read a matching index from something it does not
/// own. The chunks are disjoint and the base index is a pure function of the
/// chunk's position, so the result is the same in either form.
#[cfg(feature = "parallel")]
pub fn for_each_chunk_mut_indexed<T, F>(items: &mut [T], size: usize, f: F)
where
    T: Send,
    F: Fn(usize, &mut [T]) + Send + Sync,
{
    use rayon::prelude::*;
    items
        .par_chunks_mut(size)
        .enumerate()
        .for_each(|(k, chunk)| f(k * size, chunk));
}

#[cfg(not(feature = "parallel"))]
pub fn for_each_chunk_mut_indexed<T, F>(items: &mut [T], size: usize, f: F)
where
    F: Fn(usize, &mut [T]),
{
    items
        .chunks_mut(size)
        .enumerate()
        .for_each(|(k, chunk)| f(k * size, chunk));
}

/// Report the resident and peak memory after a prover phase, when the
/// environment asks for it with `NOX_MEM`. Linux only, which is where the
/// prover is profiled; elsewhere, and in serial builds, it does nothing.
#[cfg(feature = "parallel")]
pub fn mark(phase: &str) {
    extern crate std;
    if std::env::var_os("NOX_MEM").is_none() {
        return;
    }
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else { return };
    let kb = |key: &str| -> f64 {
        status
            .lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0)
    };
    std::eprintln!("[mem] {phase:<18} rss {:>6.2} GB  peak {:>6.2} GB", kb("VmRSS:") / 1e6, kb("VmHWM:") / 1e6);
}

#[cfg(not(feature = "parallel"))]
pub fn mark(_phase: &str) {}

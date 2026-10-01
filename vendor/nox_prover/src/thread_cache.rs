// NONOS Operating System (AGPL-3.0-or-later)
//! A per-thread cache in front of the allocator, for the threaded wasm build.
//!
//! A wasm32 build with shared memory has one allocator behind one spin lock,
//! and a proof makes millions of small allocations from every core at once:
//! eight cores in a browser proved barely faster than four, while natively
//! they scale nearly eightfold. Here each thread keeps its freed small blocks
//! in per-size-class lists and serves the next allocation of that class from
//! them, so the lock is taken only when a list is empty or overfull. Blocks
//! are interchangeable within a class, whichever thread freed them.
//!
//! Only for `wasm-threads`: a native build's allocator already has per-thread
//! arenas, and a single-threaded wasm build has nothing to contend on.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use core::ptr;
use std::alloc::System;

/// Size classes 16, 32, ..., 4096 bytes: powers of two, aligned to 16.
const MIN_SHIFT: u32 = 4;
const MAX_SHIFT: u32 = 12;
const CLASSES: usize = (MAX_SHIFT - MIN_SHIFT + 1) as usize;
const CLASS_ALIGN: usize = 16;

/// Bytes a thread may hold free in one class before it hands half back.
const CAP_BYTES: usize = 1 << 20;

pub struct Cached;

/// The threaded browser build proves from every core at once, and wasm has
/// one allocator lock: a proof's 76 million allocations queued on it.
#[global_allocator]
static ALLOCATOR: Cached = Cached;

/// A free block's first word links to the next free block of its class.
struct Free {
    next: *mut Free,
}

thread_local! {
    static HEADS: [Cell<*mut Free>; CLASSES] = const { [const { Cell::new(ptr::null_mut()) }; CLASSES] };
    static COUNTS: [Cell<usize>; CLASSES] = const { [const { Cell::new(0) }; CLASSES] };
}

/// The class of a layout, or `None` for one the cache does not serve.
fn class_of(l: &Layout) -> Option<usize> {
    if l.align() > CLASS_ALIGN || l.size() > 1 << MAX_SHIFT {
        return None;
    }
    let size = l.size().max(1 << MIN_SHIFT).next_power_of_two();
    Some((size.trailing_zeros() - MIN_SHIFT) as usize)
}

fn class_layout(c: usize) -> Layout {
    // A power of two no larger than 4096 with alignment 16 is always valid.
    unsafe { Layout::from_size_align_unchecked(1 << (c as u32 + MIN_SHIFT), CLASS_ALIGN) }
}

unsafe impl GlobalAlloc for Cached {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let Some(c) = class_of(&l) else {
            // SAFETY: forwarded unchanged.
            return unsafe { System.alloc(l) };
        };
        let hit = HEADS
            .try_with(|heads| {
                let head = heads[c].get();
                if head.is_null() {
                    return ptr::null_mut();
                }
                // SAFETY: a non-null head is a block this thread freed into
                // the list, whose first word is the link written on free.
                heads[c].set(unsafe { (*head).next });
                let _ = COUNTS.try_with(|n| n[c].set(n[c].get().saturating_sub(1)));
                head.cast::<u8>()
            })
            .unwrap_or(ptr::null_mut());
        if !hit.is_null() {
            return hit;
        }
        // SAFETY: a valid class layout.
        unsafe { System.alloc(class_layout(c)) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        let Some(c) = class_of(&l) else {
            // SAFETY: allocated by `System` with this layout.
            return unsafe { System.dealloc(p, l) };
        };
        let kept = HEADS
            .try_with(|heads| {
                let block = p.cast::<Free>();
                // SAFETY: the block is at least 16 bytes, 16-aligned, and ours.
                unsafe { (*block).next = heads[c].get() };
                heads[c].set(block);
                let over = COUNTS
                    .try_with(|n| {
                        n[c].set(n[c].get() + 1);
                        n[c].get() << (c as u32 + MIN_SHIFT) > CAP_BYTES
                    })
                    .unwrap_or(false);
                if over {
                    // Hand half the list back, so a thread that frees what
                    // others allocate does not hoard it.
                    let give = COUNTS.try_with(|n| n[c].get() / 2).unwrap_or(0);
                    for _ in 0..give {
                        let b = heads[c].get();
                        if b.is_null() {
                            break;
                        }
                        // SAFETY: as above, a block on this thread's list.
                        heads[c].set(unsafe { (*b).next });
                        // SAFETY: every class block came from `System` with
                        // the class layout.
                        unsafe { System.dealloc(b.cast(), class_layout(c)) };
                    }
                    let _ = COUNTS.try_with(|n| n[c].set(n[c].get() - give));
                }
            })
            .is_ok();
        if !kept {
            // The thread's cache is gone (thread teardown): free directly.
            // SAFETY: a class block from `System` with the class layout.
            unsafe { System.dealloc(p, class_layout(c)) };
        }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller's contract gives a valid layout for `new_size`.
        let new = unsafe { Layout::from_size_align_unchecked(new_size, l.align()) };
        match (class_of(&l), class_of(&new)) {
            // SAFETY: both outside the cache: `System` owns the block.
            (None, None) => unsafe { System.realloc(p, l, new_size) },
            (Some(a), Some(b)) if a == b => p,
            _ => {
                // SAFETY: a fresh block, the overlap copied, the old freed
                // through the path that allocated it.
                unsafe {
                    let q = self.alloc(new);
                    if !q.is_null() {
                        ptr::copy_nonoverlapping(p, q, l.size().min(new_size));
                        self.dealloc(p, l);
                    }
                    q
                }
            }
        }
    }
}

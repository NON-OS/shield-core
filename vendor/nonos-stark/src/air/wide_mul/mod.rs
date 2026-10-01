// NONOS Operating System (AGPL-3.0-or-later)

//! Wide multiplication over 16-bit limbs, the gadget behind the 256-bit value arithmetic a
//! note commitment needs. A field element is too narrow to hold a full 64-by-64 product
//! without wrapping, so a value is split into four limbs and multiplied schoolbook, each
//! output weight carrying its sum and carry. `limbs` holds the split and its range discipline,
//! `product` the schoolbook itself. Every limb is range-checked in circuit, because an
//! unbounded decomposition reassembles to anything, which is the wraparound the gadget exists
//! to prevent.

mod limbs;
mod product;

pub use limbs::{split, LIMB_BITS, LIMB_MASK, N_LIMBS};
pub use product::{wide_mul, Product, N_OUT};

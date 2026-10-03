// NONOS Operating System (AGPL-3.0-or-later)
//! The witness-mode recursion assembly: nine regions and their grand-product
//! bindings, one region or binding family per file. `build` assembles the
//! wired AIR and witness from the real inner join-split proof; `tamper` names
//! the targeted forgeries the reject gate must catch. Host tooling but `inner`,
//! which proves the join-split and builds without std.

#[cfg(feature = "std")]
mod aggregate;
#[cfg(feature = "std")]
mod cells;
#[cfg(feature = "std")]
mod compose_form;
#[cfg(feature = "std")]
pub mod finals;
#[cfg(feature = "std")]
pub mod auth;
#[cfg(feature = "std")]
pub mod build;
#[cfg(feature = "std")]
pub mod compose;
#[cfg(feature = "std")]
pub mod compose_step;
#[cfg(feature = "std")]
pub mod deep;
#[cfg(feature = "std")]
pub mod fri;
#[cfg(feature = "std")]
pub mod groups;
pub mod inner;
#[cfg(feature = "std")]
pub mod layout;
#[cfg(feature = "std")]
mod parts;
#[cfg(feature = "std")]
pub mod periodic;
#[cfg(feature = "std")]
pub mod point;
#[cfg(feature = "std")]
pub mod anchors;
#[cfg(feature = "std")]
mod gen;
#[cfg(feature = "std")]
pub mod points;
#[cfg(feature = "std")]
pub mod powers;
#[cfg(feature = "std")]
pub mod sponge;
#[cfg(feature = "std")]
pub mod strip;
#[cfg(feature = "std")]
pub mod tamper;
#[cfg(feature = "std")]
pub mod transcript;

#[cfg(feature = "std")]
pub use build::{assemble, assemble_capped, assemble_many, assemble_over, assemble_over_wired, assemble_q};
#[cfg(feature = "std")]
pub use build::{assemble_real, assemble_real_capped, assemble_real_capped_wired};
#[cfg(feature = "std")]
pub use build::{build_groups_for, Aggregate, Assembly};
#[cfg(feature = "std")]
pub use gen::{assemble_over_gen, assemble_over_gen_form, AggregateGen, AssemblyGen};
#[cfg(feature = "std")]
pub use compose_form::ComposeForm;
#[cfg(feature = "std")]
pub use tamper::Tamper;

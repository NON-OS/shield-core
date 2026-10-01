// NONOS Operating System (AGPL-3.0-or-later)
//! The witness-mode recursion assembly: nine regions and their grand-product
//! bindings, one region or binding family per file. `build` assembles the
//! wired AIR and witness from the real inner join-split proof; `tamper` names
//! the targeted forgeries the reject gate must catch.

mod aggregate;
mod cells;
mod compose_form;
pub mod finals;
pub mod auth;
pub mod build;
pub mod compose;
pub mod compose_step;
pub mod deep;
pub mod fri;
pub mod groups;
pub mod inner;
pub mod layout;
mod parts;
pub mod periodic;
pub mod point;
pub mod anchors;
mod gen;
pub mod points;
pub mod powers;
pub mod sponge;
pub mod strip;
pub mod tamper;
pub mod transcript;

pub use build::{assemble, assemble_capped, assemble_many, assemble_over, assemble_over_wired, assemble_q};
pub use build::{assemble_real, assemble_real_capped, assemble_real_capped_wired};
pub use build::{build_groups_for, Aggregate, Assembly};
pub use gen::{assemble_over_gen, assemble_over_gen_form, AggregateGen, AssemblyGen};
pub use compose_form::ComposeForm;
pub use tamper::Tamper;

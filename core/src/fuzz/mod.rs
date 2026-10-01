//! Fuzz entry points for every parser fed bytes this wallet did not write. The property is no
//! panic, no endless loop and no unbounded allocation, and shipped builds carry none of it.

mod address;
mod local;
mod note;
mod replies;
mod rpc;
mod store;

#[cfg(test)]
#[path = "sweep_test.rs"]
mod sweep_test;

pub use address::address;
pub use local::{disk, typed};
pub use note::note;
pub use replies::{account, lander, policy};
pub use rpc::rpc;
pub use store::{frame, row};

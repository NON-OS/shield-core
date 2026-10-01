//! The wallet the shells hold. Its session sits behind a lock, so any thread can call it.

mod access;
mod account;
mod account_confirm;
mod account_send;
mod account_swap;
mod account_view;
mod accounts;
mod chain;
mod deposit;
mod export;
mod fee;
mod find;
mod find_steps;
mod follow;
mod import;
mod lifecycle;
mod measure;
mod new;
mod own;
mod pending;
mod pending_batch;
mod profile;
mod publish;
mod publish_view;
mod quote;
mod quote_view;
mod relay;
mod rewards;
mod settle_self;
mod shield;
mod shield_split;
mod shield_view;
mod spend;
mod swap_rate;
mod swap_view;
mod sync_each;
mod take_back;
mod ticket;
mod watching;
mod wipe;
mod withdraw_to;
mod words;

use crate::custody::HardwareGuard;
use crate::net::tor::Tor;
use crate::wallet::{Paths, Session};
use pending::Pending;
use pending_batch::PendingBatch;
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::{Arc, Mutex};

#[derive(uniffi::Object)]
pub struct Wallet {
    paths: Paths,
    guard: Arc<dyn HardwareGuard>,
    session: Mutex<Option<Session>>,
    tor: Mutex<Option<Arc<Tor>>>,
    pending: Mutex<Option<Pending>>,
    quoted: Mutex<Option<quote::Quoted>>,
    batch: Mutex<Option<PendingBatch>>,
    reviews: AtomicU64,
    /// The active account, for the Tor client to route by without taking the session lock.
    active: AtomicU32,
    searched: AtomicU32,
}

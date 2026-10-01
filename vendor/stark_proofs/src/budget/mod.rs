// NONOS Operating System (AGPL-3.0-or-later)

//! The five budgets a settlement has to fit at once: proof bytes, calldata
//! pricing, transaction gas, soundness, and proving cost. Nothing here proves
//! or verifies anything. It is the arithmetic that decides which parameter
//! point is worth proving in the first place.

mod evm;
mod gas;
mod search;
#[cfg(test)]
mod tests;

pub use evm::{execution_budget, memory_gas, memory_gas_over_queries, transaction_gas};
pub use evm::{tokens, tokens_estimated};
pub use evm::{BASE_TX_GAS, FLOOR_GAS_PER_TOKEN, GAS_PER_TOKEN, TOKENS_PER_NONZERO_BYTE, TX_GAS_CAP};
pub use gas::{nodes_per_query, query_cost, verify_gas, CostModel, QueryCost};
pub use search::{deep_terms, evaluate, params_at, rate_exponent, search, soundness};
pub use search::{Evaluated, Limits, Point};

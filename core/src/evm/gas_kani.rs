//! Proved for every base fee, suggested tip and estimate, not sampled.

use super::{limit, offer, CEILING, ETHER_MARGIN, FLOOR, MAX_TIP};

/// Whatever an RPC says, an offer never passes the ceiling or the tip cap,
/// and its tip never exceeds its fee cap, which EIP-1559 requires of a
/// transaction the chain will take.
#[kani::proof]
fn an_offer_is_always_one_the_chain_accepts_and_never_overpays() {
    let (base, suggested): (u128, u128) = (kani::any(), kani::any());
    if let Some(f) = offer(base, suggested) {
        assert!(f.max_fee <= CEILING);
        assert!(f.max_priority_fee <= MAX_TIP);
        assert!(f.max_priority_fee <= f.max_fee);
        assert!(f.max_fee >= base);
    }
}

/// No gas limit is below the estimate, ether never gets less than 21,000 or
/// more than the estimate and `ETHER_MARGIN`, and any estimate that fits a
/// gas limit gives one.
#[kani::proof]
fn a_gas_limit_is_never_below_the_estimate_and_ether_stays_near_it() {
    let estimate: u128 = kani::any();
    let plain: bool = kani::any();
    if let Some(gas) = limit(estimate, plain) {
        assert!(u128::from(gas) >= estimate);
        if plain {
            assert!(u128::from(gas) >= FLOOR);
            assert!(u128::from(gas) <= estimate.max(FLOOR).saturating_add(ETHER_MARGIN));
        }
    } else if plain {
        assert!(estimate.saturating_add(ETHER_MARGIN) > u128::from(u64::MAX));
    }
}

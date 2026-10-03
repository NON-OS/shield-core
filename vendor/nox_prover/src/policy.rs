// NONOS Operating System (AGPL-3.0-or-later)
//! The anonymity defaults a request must meet before anything is proved.
//!
//! - A spend is submitted by someone else: it pays a nonzero fee to a named
//!   `fee_recipient`. `"self_submit": true` opts out.
//! - A public amount, and every output keyed to someone other than the
//!   spender, is a standard size. Change is exempt whether it is named
//!   `"self"` or by the spender's own spend key, which is how an HD wallet
//!   keeps change it can recover from its seed phrase. Standard sizes are
//!   `unit * {1, 2, 5} * 10^k`, `unit` 0.001 of the asset unless the request
//!   states one: 10^15 wei for ETH (asset 0), 10^6 note units of 10^9 base
//!   units for NOX (asset 1). `"any_amount": true` opts out.
//!
//! When a submission may go out and which address a withdrawal pays are the
//! calling wallet's to decide. An opt-out is
//! never silent: `check` returns it by name, and `prove` puts it in the
//! proof's JSON.

use stark_proofs::crypto::stark::air::{Poseidon, RATE};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::host::{try_unpack_digest, Json};
use stark_proofs::shield::key::derive;
use stark_proofs::shield::live_seed::seed_notes;
use stark_proofs::shield::note::POOL_LOG_ROUNDS;

/// 0.001 of an 18 decimal token.
pub const UNIT: u64 = 1_000_000_000_000_000;

/*
 * The smallest standard note per asset, in note units: the units the pool
 * counts a note's value in. ETH (asset 0) counts wei, so 0.001 ETH is 10^15.
 * NOX (asset 1) counts 10^9 base units per note unit, so 0.001 NOX is 10^6.
 * The launch pool's asset table; an asset not here must state its unit.
 */
pub const ASSET_UNITS: [(u64, u64); 2] = [(0, 1_000_000_000_000_000), (1, 1_000_000)];

/// The standard unit of `asset_id`, from the launch pool's asset table.
pub fn unit_for(asset_id: u64) -> Option<u64> {
    ASSET_UNITS.iter().find(|(a, _)| *a == asset_id).map(|(_, u)| *u)
}

/// Whether `v` is one of the standard sizes of `unit`.
pub fn is_standard(v: u64, unit: u64) -> bool {
    if unit == 0 || v == 0 || !v.is_multiple_of(unit) {
        return false;
    }
    let mut m = v / unit;
    while m.is_multiple_of(10) {
        m /= 10;
    }
    matches!(m, 1 | 2 | 5)
}

fn flag(req: &Json<'_>, name: &str) -> bool {
    req.has(name) && req.try_field(name).map(|v| v.starts_with("true")).unwrap_or(false)
}

/// The spender's own spend keys, derived from the seed's secrets rather than
/// read from the keys the seed file claims. Empty when the seed does not
/// parse; the build refuses that seed by name afterwards.
pub fn own_keys(seed: &str) -> Vec<[Fp; RATE]> {
    let h = Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE]);
    match seed_notes(seed) {
        Ok((sks, _)) => sks.iter().map(|sk| derive(&h, *sk).spend_pk).collect(),
        Err(_) => Vec::new(),
    }
}

/// The request's opt-outs, or why it is refused. `own` holds the spender's
/// spend keys (`own_keys`): an output keyed to one of them is change.
pub fn check(request: &str, own: &[[Fp; RATE]]) -> Result<Vec<&'static str>, String> {
    let req = Json(request);
    let mut weakened = Vec::new();

    if flag(&req, "self_submit") {
        weakened.push("self_submit");
    } else if req.try_u64("fee")? == 0 {
        return Err(
            "a spend goes out through a submitter by default: set a nonzero fee and its fee_recipient, \
             or \"self_submit\": true to send it from your own address"
                .to_string(),
        );
    }

    if flag(&req, "any_amount") {
        weakened.push("any_amount");
    } else {
        let unit = if req.has("unit") {
            req.try_u64("unit")?
        } else {
            let asset = if req.has("asset_id") { req.try_u64("asset_id")? } else { 0 };
            unit_for(asset).ok_or_else(|| {
                format!("asset {asset} has no standard unit in the table; state it with \"unit\"")
            })?
        };
        let public = req.try_u64("public_amount")?;
        if public != 0 && !is_standard(public, unit) {
            return Err(format!(
                "public amount {public} is not a standard size of {unit}; split it, or set \"any_amount\": true"
            ));
        }
        let values = req.try_u64s("output_values")?;
        let foreign: Vec<bool> = if req.has("output_spend_pk") {
            let named = req.try_strings("output_spend_pk")?;
            let mut f = Vec::with_capacity(named.len());
            for w in named {
                f.push(w != "self" && !own.contains(&try_unpack_digest(w)?));
            }
            f
        } else {
            vec![false; values.len()]
        };
        for (v, f) in values.iter().zip(foreign) {
            if f && !is_standard(*v, unit) {
                return Err(format!(
                    "the payee's note of {v} is not a standard size of {unit}; split the payment, or set \"any_amount\": true"
                ));
            }
        }
    }
    Ok(weakened)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(extra: &str) -> String {
        format!(
            "{{\"fee\": 1000000000000000, \"fee_recipient\": \"0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b\", \
             \"public_amount\": 0, \"output_values\": [5000000000000000, 1234], \
             \"output_spend_pk\": [\"0x01\", \"self\"]{extra}}}"
        )
    }

    #[test]
    fn the_standard_sizes_are_the_one_two_five_series() {
        for m in [1u64, 2, 5, 10, 20, 50, 100, 5000] {
            assert!(is_standard(m * UNIT, UNIT), "{m}");
        }
        for m in [3u64, 4, 7, 11, 15, 150] {
            assert!(!is_standard(m * UNIT, UNIT), "{m}");
        }
        assert!(!is_standard(0, UNIT) && !is_standard(UNIT + 1, UNIT));
    }

    #[test]
    fn a_relayed_standard_payment_passes_with_nothing_weakened() {
        assert_eq!(check(&req(""), &[]), Ok(vec![]));
    }

    #[test]
    fn no_fee_means_self_submission_and_is_refused_unless_opted_into() {
        let r = req("").replace("\"fee\": 1000000000000000", "\"fee\": 0");
        assert!(check(&r, &[]).is_err());
        let opted = r.replace("}", ", \"self_submit\": true}");
        assert_eq!(check(&opted, &[]), Ok(vec!["self_submit"]));
    }

    #[test]
    fn a_payee_note_off_the_standard_sizes_is_refused_unless_opted_into() {
        let r = req("").replace("[5000000000000000, 1234]", "[3000000000000000, 1234]");
        assert!(check(&r, &[]).is_err());
        assert_eq!(check(&req(", \"any_amount\": true").replace("[5000000000000000", "[3000000000000000"), &[]), Ok(vec!["any_amount"]));
    }

    /// Change keyed to the spender's own spend key is change, not a payment:
    /// an HD wallet names it that way so the note is recoverable from the
    /// seed phrase, and it keeps the exemption `"self"` has.
    #[test]
    fn change_to_the_spenders_own_key_is_exempt() {
        let h = Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE]);
        let mine = derive(&h, [Fp::from_u64(7), Fp::from_u64(8), Fp::from_u64(9), Fp::from_u64(10)]).spend_pk;
        let word = stark_proofs::host::pack_u256(&mine);
        let r = req("").replace("\"self\"]", &format!("\"{word}\"]"));
        assert_eq!(check(&r, &[mine]), Ok(vec![]), "change to the spender's own key was held to a standard size");
        assert!(check(&r, &[]).is_err(), "a key that is not the spender's got the change exemption");
    }

    /// NOX notes count 10^9 base units, so its standard sizes are a
    /// million times smaller in note units than ETH's.
    #[test]
    fn the_unit_follows_the_asset() {
        // 0.005 NOX is 5 * 10^6 note units: standard for NOX, and not even a
        // multiple of the ETH unit.
        let small = |asset: u64| {
            req(&format!(", \"asset_id\": {asset}")).replace("[5000000000000000, 1234]", "[5000000, 1234]")
        };
        assert_eq!(check(&small(1), &[]), Ok(vec![]), "0.005 NOX was refused");
        assert!(check(&small(0), &[]).is_err(), "5 * 10^6 wei passed as a standard ETH note");
        assert!(check(&req(", \"asset_id\": 9"), &[]).is_err(), "an unknown asset was given a unit");
    }

    #[test]
    fn a_withdrawal_amount_off_the_standard_sizes_is_refused() {
        let r = req("").replace("\"public_amount\": 0", "\"public_amount\": 1300000000000000");
        assert!(check(&r, &[]).is_err());
    }
}

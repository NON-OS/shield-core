// NONOS Operating System (AGPL-3.0-or-later)
//! The public words as the artifact presents them: the flat limb list the
//! transcript absorbed, and the same words as the pool reads them.

/// Four limbs as the 256 bit word the pool carries them in, limb 0 lowest,
/// as a 0x hex string.
pub fn pack_u256(limbs: &[stark_proofs::crypto::stark::field::Fp]) -> String {
    let mut v: u128 = 0;
    let mut hi: u128 = 0;
    for (i, l) in limbs.iter().enumerate() {
        let x = l.to_u64() as u128;
        match i {
            0 => v |= x,
            1 => v |= x << 64,
            2 => hi |= x,
            _ => hi |= x << 64,
        }
    }
    format!("0x{hi:032x}{v:032x}")
}

/// The public words as the pool presents them, eleven per intent in SPEC
/// section 6 order, emitted beside the flat limb list they must equal.
pub fn pool_intents(publics: &[stark_proofs::crypto::stark::field::Fp]) -> Vec<String> {
    use stark_proofs::shield::join::publics::{
        ASSET_ID, CLEARING_PRICE, FEE, PUBLIC_AMOUNT, RECIPIENT, WORDS,
    };
    publics
        .as_chunks::<WORDS>().0.iter()
        .map(|w| {
            let mut words: Vec<String> = Vec::with_capacity(11);
            for d in 0..6 {
                words.push(pack_u256(&w[4 * d..4 * d + 4]));
            }
            for i in [PUBLIC_AMOUNT, FEE, ASSET_ID, CLEARING_PRICE] {
                words.push(format!("0x{:x}", w[i].to_u64()));
            }
            words.push(pack_u256(&w[RECIPIENT..RECIPIENT + 4]));
            format!(
                "{{\"words\": [{}]}}",
                words
                    .iter()
                    .map(|s| format!("\"{s}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .collect()
}


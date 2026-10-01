// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::RATE;
use crate::crypto::stark::field::Fp;

/// An EVM address, the twenty bytes as they appear on chain, most significant
/// first.
pub type Address = [u8; 20];

/// Terms the circuit does not compute: the settlement destination and the batch
/// clearing price. They are
/// inputs to the statement rather than outputs of it, so a boundary is the whole
/// binding: the proof is void for any other value, which is what stops a settler
/// substituting one. Price uniformity across a batch is a separate constraint
/// and lands with the batch assembly.
#[derive(Clone, Copy)]
pub struct Settle {
    pub clearing_price: u64,
    pub recipient: Address,
    /// Who the pool pays the fee to. Bound by the proof, so whoever submits the
    /// settlement cannot redirect the fee to themselves by copying it.
    pub fee_recipient: Address,
    /// The earliest settlement time, carried into the statement as word 36
    /// under the `not_before` build and ignored otherwise.
    pub not_before: u64,
}

/// Bits per address limb. Below 64 on purpose: a 64 bit limb can be p or
/// more, and `Fp::from_u64` reduces it, so the address whose low 64 bits are
/// `v >= p` and the one whose low bits are `v - p` published the same limbs,
/// and the chain, which refuses a limb that is not canonical, could pay
/// neither. 48 bit limbs are always canonical, and three of them and a 16 bit
/// fourth are the 160 bits exactly.
pub const ADDRESS_LIMB_BITS: u32 = 48;

/// The address as the four Goldilocks limbs the intent carries: read as a 160
/// bit big-endian integer, limb i is its bits `48i .. 48i + 48`, so limbs 0 to
/// 2 hold 48 bits each and limb 3 the top 16. Every limb is below 2^48 and so
/// below p, and the map is injective: bytes 14..20 are limb 0, 8..14 limb 1,
/// 2..8 limb 2, 0..2 limb 3.
pub fn address_limbs(a: &Address) -> [Fp; RATE] {
    let be = |bytes: &[u8]| bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
    [
        Fp::from_u64(be(&a[14..20])),
        Fp::from_u64(be(&a[8..14])),
        Fp::from_u64(be(&a[2..8])),
        Fp::from_u64(be(&a[0..2])),
    ]
}

/// The inverse of `address_limbs`, refusing limbs no address produces: any of
/// the first three at 2^48 or more, or the fourth at 2^16 or more. Accepting
/// them would name an address other than the one the limbs came from.
pub fn address_of_limbs(limbs: &[Fp; RATE]) -> Option<Address> {
    let v: [u64; RATE] = core::array::from_fn(|i| limbs[i].to_u64());
    if v[..3].iter().any(|&l| l >> ADDRESS_LIMB_BITS != 0) || v[3] >> 16 != 0 {
        return None;
    }
    let mut a = [0u8; 20];
    a[14..20].copy_from_slice(&v[0].to_be_bytes()[2..8]);
    a[8..14].copy_from_slice(&v[1].to_be_bytes()[2..8]);
    a[2..8].copy_from_slice(&v[2].to_be_bytes()[2..8]);
    a[0..2].copy_from_slice(&v[3].to_be_bytes()[6..8]);
    Some(a)
}

/// An address whose value is a small integer, for fixtures that name a
/// recipient rather than pay one. `0xBEEF` is the address with `0xBEEF` in
/// its low bytes and zeros above.
pub const fn address_from_u64(v: u64) -> Address {
    let b = v.to_be_bytes();
    let mut a = [0u8; 20];
    let mut i = 0;
    while i < 8 {
        a[12 + i] = b[i];
        i += 1;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limbs_of_an_address_split_at_48_bit_boundaries() {
        let mut a = [0u8; 20];
        for (i, b) in a.iter_mut().enumerate() {
            *b = 0xA0 + i as u8;
        }
        let l = address_limbs(&a);
        assert_eq!(l[0].to_u64(), 0xAEAF_B0B1_B2B3);
        assert_eq!(l[1].to_u64(), 0xA8A9_AAAB_ACAD);
        assert_eq!(l[2].to_u64(), 0xA2A3_A4A5_A6A7);
        assert_eq!(l[3].to_u64(), 0xA0A1);
        assert_eq!(address_of_limbs(&l), Some(a));
    }

    /// The addresses the 64 bit layout could not carry: low 64 bits at p or
    /// above, where the limb reduced onto another address's. Both now have
    /// canonical limbs of their own, and the two differ.
    #[test]
    fn an_address_above_p_in_its_low_bits_keeps_its_own_limbs() {
        let p = 0xFFFF_FFFF_0000_0001u64;
        let mut hi = [0u8; 20];
        hi[12..20].copy_from_slice(&(p + 5).to_be_bytes());
        let mut lo = [0u8; 20];
        lo[12..20].copy_from_slice(&5u64.to_be_bytes());
        let (lh, ll) = (address_limbs(&hi), address_limbs(&lo));
        assert!(lh.iter().all(|v| v.to_u64() < 1 << ADDRESS_LIMB_BITS));
        assert_ne!(lh, ll, "two addresses share one encoding");
        assert_eq!(address_of_limbs(&lh), Some(hi));
    }

    /// Limbs out of range name no address and are refused, not truncated.
    #[test]
    fn limbs_no_address_produces_are_refused() {
        assert_eq!(
            address_of_limbs(&[1u64 << 48, 0, 0, 0].map(Fp::from_u64)),
            None
        );
        assert_eq!(
            address_of_limbs(&[0, 0, 0, 1u64 << 16].map(Fp::from_u64)),
            None
        );
    }

    #[test]
    fn a_small_address_lands_in_the_low_limb() {
        let l = address_limbs(&address_from_u64(0xBEEF));
        assert_eq!(l[0].to_u64(), 0xBEEF);
        assert!(l[1..].iter().all(|v| v.to_u64() == 0));
    }
}

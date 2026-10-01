// NONOS Operating System (AGPL-3.0-or-later)

//! The composition polynomial over the evaluation domain, built one block of rows at a time.
//! At each point it evaluates the AIR's transition and boundary constraints on the trace
//! window, batches them under the transcript coefficients, and divides by the domain vanishing
//! polynomial, so the result is a genuine polynomial exactly when every constraint holds. The
//! block size trades memory for call overhead; the pass streams like the others, so the whole
//! composition is never held at once.

use super::super::super::field::{Fp, Fp2};
use super::super::super::poly::{intt, lde_from_coeffs};
use super::super::composition::{compose_base_planned, ComposePlan};
use super::super::spec::AirExt;
use super::coset::extend;
use super::setup::Domain;
use alloc::vec::Vec;

/// Rows go to threads in blocks: a block allocates its window once, clears and
/// reuses it, and carries its own point forward multiplicatively.
pub(in crate::air) const BLOCK: usize = 1024;

/// The composition over the whole domain.
///
/// The composition is a polynomial of degree below the constraint degree times
/// the longest trace polynomial, which is a small multiple of the trace
/// length, while the domain is the trace length times the blowup. So the
/// constraints are evaluated only on the `k` cosets whose union is one coset
/// of the size `k t` subgroup, enough points to determine that polynomial,
/// which is interpolated once and extended onto every coset. The values are
/// the ones evaluating every coset would give, because they are one polynomial
/// on the same points; `sampled_equals_evaluated` holds the two paths equal.
/// Where `k` would reach the blowup nothing is saved and every coset is
/// evaluated.
pub(in crate::air) fn over_domain<A: AirExt>(
    air: &A,
    d: &Domain,
    trace: &[Vec<Fp>],
    periodic: &[Vec<Fp>],
    coeffs: &[Fp2],
) -> Vec<Fp2> {
    let plan = ComposePlan::new(air, d.g);
    let k = sample_cosets(air, d, trace);
    if k >= d.blowup {
        return evaluated(air, &plan, d, trace, periodic, coeffs);
    }
    sampled(air, &plan, d, trace, periodic, coeffs, k)
}

/// Cosets needed to determine the composition: a power of two with
/// `k t > constraint_degree * longest_trace_polynomial`. The bound ignores the
/// division by the vanishing polynomial, which only lowers the degree, so it
/// never samples too few.
///
/// The mask pair is left out of the longest: no constraint reads a mask
/// column, so the composition does not depend on it, and its degree of
/// nearly B would otherwise size the bound past every coset and make the
/// launch prover evaluate the whole domain where a quarter of it determines
/// the composition.
pub(in crate::air) fn sample_cosets<A: AirExt>(air: &A, d: &Domain, trace: &[Vec<Fp>]) -> usize {
    let masks = air.mask_pair();
    let longest = trace
        .iter()
        .enumerate()
        .filter(|(i, _)| masks.is_none_or(|(a, b)| *i != a && *i != b))
        .map(|(_, c)| c.len())
        .max()
        .unwrap_or(0)
        .max(d.t);
    let bound = air.constraint_degree().max(1) * longest + 1;
    bound.div_ceil(d.t).next_power_of_two()
}

/// The composition on coset `c`: position `c + blowup * i` for `i` in `0..t`.
fn coset<A: AirExt>(
    air: &A,
    plan: &ComposePlan,
    d: &Domain,
    trace: &[Vec<Fp>],
    periodic: &[Vec<Fp>],
    coeffs: &[Fp2],
    c: usize,
) -> Vec<Fp2> {
    let cols = extend(trace, d, c);
    let per = extend(periodic, d, c);
    let shift_c = d.coset_shift(c);
    let z_h_inv = plan.vanishing_inv(shift_c);
    let blocks = d.t.div_ceil(BLOCK);
    let parts = crate::par::map_index(blocks, |b| {
        let (lo, hi) = (b * BLOCK, ((b + 1) * BLOCK).min(d.t));
        let mut window: Vec<Fp> = Vec::with_capacity(d.window * d.width);
        let mut periodic_i: Vec<Fp> = Vec::with_capacity(per.len());
        let mut out: Vec<Fp2> = Vec::with_capacity(hi - lo);
        // The denominator set and its prefixes, owned by the block so the
        // per point inversion allocates nothing.
        let mut den: Vec<Fp> = Vec::new();
        let mut prefix: Vec<Fp> = Vec::new();
        let mut x = shift_c * d.sub.pow(lo as u64);
        for i in lo..hi {
            window.clear();
            for k in 0..d.window {
                let row = (i + k) % d.t;
                for col in &cols {
                    window.push(col[row]);
                }
            }
            periodic_i.clear();
            periodic_i.extend(per.iter().map(|p| p[i]));
            out.push(compose_base_planned(
                air,
                plan,
                x,
                z_h_inv,
                &window,
                &periodic_i,
                coeffs,
                &mut den,
                &mut prefix,
            ));
            x = x * d.sub;
        }
        out
    });
    parts.into_iter().flatten().collect()
}

/// Every coset evaluated.
///
/// The window at position `j` reads `(j + k * blowup) % n`, which shares j's
/// residue mod blowup: a window never leaves its coset, it wraps to row
/// `(i + k) % t` of the same one. That wrap is what makes streaming exact.
///
/// Every point of the domain is a base field element and so is every trace
/// and periodic value at it, so the constraints are evaluated in the base
/// field and only the coefficient products lift.
pub(in crate::air) fn evaluated<A: AirExt>(
    air: &A,
    plan: &ComposePlan,
    d: &Domain,
    trace: &[Vec<Fp>],
    periodic: &[Vec<Fp>],
    coeffs: &[Fp2],
) -> Vec<Fp2> {
    let mut comp_d = alloc::vec![Fp2::ZERO; d.n];
    for c in 0..d.blowup {
        for (i, v) in coset(air, plan, d, trace, periodic, coeffs, c).into_iter().enumerate() {
            comp_d[c + d.blowup * i] = v;
        }
    }
    comp_d
}

/// `k` cosets evaluated, the rest extended.
///
/// Cosets `0, s, 2s, ..`, with `s = blowup / k`, together are the points
/// `shift * w^m` for `w = omega^s` of order `k t`, position `m = c' + k i` for
/// coset `c' s` and row `i`. Interpolating there gives the polynomial
/// `Q(X) = P(shift X)`, and coset `c` of the full domain is
/// `P(shift omega^c sub^i) = Q(omega^c sub^i)`: an extension of `Q` onto the
/// coset `omega^c` of the trace subgroup. Each lane of the extension field is a
/// base field polynomial of its own.
fn sampled<A: AirExt>(
    air: &A,
    plan: &ComposePlan,
    d: &Domain,
    trace: &[Vec<Fp>],
    periodic: &[Vec<Fp>],
    coeffs: &[Fp2],
    k: usize,
) -> Vec<Fp2> {
    let step = d.blowup / k;
    let len = k * d.t;
    let mut lo = alloc::vec![Fp::ZERO; len];
    let mut hi = alloc::vec![Fp::ZERO; len];
    for c in 0..k {
        for (i, v) in coset(air, plan, d, trace, periodic, coeffs, c * step).into_iter().enumerate() {
            lo[c + k * i] = v.c0;
            hi[c + k * i] = v.c1;
        }
    }
    let w = d.omega.pow(step as u64);
    let lanes = crate::par::map_slice(&[lo, hi], |lane| intt(lane, w));
    let (q0, q1) = (&lanes[0], &lanes[1]);
    let cosets = crate::par::map_index(d.blowup, |c| {
        let at = d.omega.pow(c as u64);
        let a = lde_from_coeffs(q0, at, d.sub, d.t);
        let b = lde_from_coeffs(q1, at, d.sub, d.t);
        (a, b)
    });
    let mut comp_d = alloc::vec![Fp2::ZERO; d.n];
    for (c, (a, b)) in cosets.into_iter().enumerate() {
        for i in 0..d.t {
            comp_d[c + d.blowup * i] = Fp2 { c0: a[i], c1: b[i] };
        }
    }
    comp_d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::composition::num_coeffs;
    use crate::air::fibonacci::Fibonacci;
    use crate::air::prove_ext::coset::trace_coeffs;
    use crate::air::squaring::Squaring;
    use crate::poly::blind_coeffs;

    fn coeffs(n: usize) -> Vec<Fp2> {
        (0..n as u64)
            .map(|k| Fp2 { c0: Fp::from_u64(3 + 5 * k), c1: Fp::from_u64(11 + 7 * k) })
            .collect()
    }

    fn blinded(tc: Vec<Vec<Fp>>, t: usize, len: usize) -> Vec<Vec<Fp>> {
        let r: Vec<Fp> = (0..len as u64).map(|k| Fp::from_u64(1_000 + 13 * k)).collect();
        tc.into_iter().map(|cf| blind_coeffs(&cf, t, &r)).collect()
    }

    fn both<A: AirExt>(air: &A, trace: &[Fp], extra: u32, blind: usize) {
        let d = Domain::of(air, extra);
        let mut tc = trace_coeffs(trace, &d);
        if blind > 0 {
            tc = blinded(tc, d.t, blind);
        }
        let cf = coeffs(num_coeffs(air));
        let plan = ComposePlan::new(air, d.g);
        let k = sample_cosets(air, &d, &tc);
        assert!(k < d.blowup, "nothing to sample at blowup {}", d.blowup);
        let whole = evaluated(air, &plan, &d, &tc, &[], &cf);
        let fast = sampled(air, &plan, &d, &tc, &[], &cf, k);
        assert_eq!(whole, fast, "the sampled composition moved at k = {k}, blowup {}", d.blowup);
        assert_eq!(over_domain(air, &d, &tc, &[], &cf), whole);
    }

    /// The sampled composition is the evaluated one, value for value, at degree one and two,
    /// with and without blinding, which is what lengthens a column past the trace.
    #[test]
    fn sampled_equals_evaluated() {
        let fib = Fibonacci { log_t: 6 };
        let mut f = alloc::vec![Fp::ONE; 64];
        for i in 2..64 {
            f[i] = f[i - 1] + f[i - 2];
        }
        both(&fib, &f, 4, 0);
        both(&fib, &f, 4, 9);

        let sq = Squaring { log_t: 6, seed: Fp::from_u64(3) };
        let mut s = alloc::vec![Fp::from_u64(3); 64];
        for i in 1..64 {
            s[i] = s[i - 1] * s[i - 1];
        }
        both(&sq, &s, 4, 0);
        both(&sq, &s, 5, 18);
    }

    /// A degree two circuit at the shipped trace length and extra blowup, with a column
    /// fourteen coefficients past the trace as blinding leaves it, samples four cosets of 512;
    /// the shipped circuit's degree eight samples sixteen of 2048.
    #[test]
    fn the_sample_is_small() {
        let sq = Squaring { log_t: 18, seed: Fp::from_u64(3) };
        let d = Domain::of(&sq, 7);
        let tc: Vec<Vec<Fp>> = alloc::vec![alloc::vec![Fp::ZERO; d.t + 14]];
        assert_eq!(d.blowup, 512);
        assert_eq!(sample_cosets(&sq, &d, &tc), 4);
    }
}

//! The wide trace commitments on the GPU, where the worker found one that agrees with the cores.
//! The prover calls the committer from the thread that holds the proof; the worker's
//! `shieldCommit` blocks there until the GPU answers. The prover checks the tree it gets back
//! against its own arithmetic and proves again without it if it is wrong, so the GPU can cost
//! time and never a proof.

use nonos_stark::committer::{clear_committer, set_committer, set_deep, set_ext_committer, DeepJob, WideCommit};
use nonos_stark::field::{Fp, Fp2};
use nonos_stark::merkle::{hash_leaf_wide, MerkleTree};
use nonos_stark::fri::root_of_unity;
use nonos_stark::poly::lde_from_coeffs;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch, js_namespace = globalThis, js_name = shieldCommit)]
    #[allow(clippy::too_many_arguments)]
    fn shield_commit(
        coeffs: &[u32],
        w: u32,
        len: u32,
        shifts: &[u32],
        twiddles: &[u32],
        t: u32,
        blowup: u32,
        cut: u32,
    ) -> Result<Option<Vec<u32>>, JsValue>;
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch, js_namespace = globalThis, js_name = shieldExtTree)]
    fn shield_ext_tree(values: &[u32], cut: u32) -> Result<Option<Vec<u32>>, JsValue>;
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch, js_namespace = globalThis, js_name = shieldDeep)]
    #[allow(clippy::too_many_arguments)]
    fn shield_deep(
        coeffs: &[u32],
        w: u32,
        len: u32,
        shifts: &[u32],
        twiddles: &[u32],
        powers: &[u32],
        t: u32,
        blowup: u32,
        comp: &[u32],
        consts: &[u32],
        window: u32,
        out: &mut [u32],
    ) -> Result<bool, JsValue>;
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::too_many_arguments)]
fn shield_deep(
    _: &[u32],
    _: u32,
    _: u32,
    _: &[u32],
    _: &[u32],
    _: &[u32],
    _: u32,
    _: u32,
    _: &[u32],
    _: &[u32],
    _: u32,
    _: &mut [u32],
) -> Result<bool, JsValue> {
    Ok(false)
}

#[cfg(not(target_arch = "wasm32"))]
fn shield_ext_tree(_: &[u32], _: u32) -> Result<Option<Vec<u32>>, JsValue> {
    Ok(None)
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::too_many_arguments)]
fn shield_commit(
    _: &[u32],
    _: u32,
    _: u32,
    _: &[u32],
    _: &[u32],
    _: u32,
    _: u32,
    _: u32,
) -> Result<Option<Vec<u32>>, JsValue> {
    Ok(None)
}

fn words(xs: impl Iterator<Item = Fp>) -> Vec<u32> {
    xs.flat_map(|x| [x.value() as u32, (x.value() >> 32) as u32]).collect()
}

fn fields(w: &[u32]) -> Vec<Fp> {
    w.chunks_exact(2).map(|p| Fp::from_u64(u64::from(p[0]) | (u64::from(p[1]) << 32))).collect()
}

/// Levels of digests from eight words each, level by level from `first` leaves down to one.
fn levels(w: &[u32], first: usize) -> Option<Vec<Vec<[u8; 32]>>> {
    let mut out = Vec::new();
    let (mut at, mut len) = (0usize, first);
    while len >= 1 {
        let level: Vec<[u8; 32]> = w
            .get(8 * at..8 * (at + len))?
            .chunks_exact(8)
            .map(|d| {
                let mut b = [0u8; 32];
                for (q, word) in d.iter().enumerate() {
                    b[4 * q..4 * q + 4].copy_from_slice(&word.to_le_bytes());
                }
                b
            })
            .collect();
        out.push(level);
        at += len;
        if len == 1 {
            break;
        }
        len /= 2;
    }
    Some(out)
}

fn on_gpu(job: &WideCommit<'_>) -> Option<Vec<Vec<[u8; 32]>>> {
    let len = job.coeffs.iter().map(Vec::len).max()?;
    // Columns padded with zeros to one length: a zero coefficient changes no value.
    let coeffs = words(job.coeffs.iter().flat_map(|c| c.iter().copied().chain(core::iter::repeat_n(Fp::ZERO, len - c.len()))));
    let got = shield_commit(
        &coeffs,
        job.coeffs.len() as u32,
        len as u32,
        &words(job.shifts.iter().copied()),
        &words(job.twiddles.iter().copied()),
        job.t as u32,
        job.blowup as u32,
        job.cut as u32,
    )
    .ok()??;
    levels(&got, (job.t * job.blowup) >> job.cut)
}

fn ext_on_gpu(values: &[Fp2], cut: usize) -> Option<Vec<Vec<[u8; 32]>>> {
    let got = shield_ext_tree(&words(values.iter().flat_map(|v| [v.c0, v.c1])), cut as u32).ok()??;
    levels(&got, values.len() >> cut)
}

fn powers(x: Fp, n: usize) -> impl Iterator<Item = Fp> {
    let mut p = Fp::ONE;
    (0..n).map(move |_| {
        let here = p;
        p = p * x;
        here
    })
}

fn deep_on_gpu(job: &DeepJob<'_>) -> Option<Vec<Fp2>> {
    let len = job.combined.iter().map(Vec::len).max()?;
    let coeffs = words(job.combined.iter().flat_map(|c| c.iter().copied().chain(core::iter::repeat_n(Fp::ZERO, len - c.len()))));
    let mut consts: Vec<Fp2> = job.zks.to_vec();
    consts.push(job.z);
    consts.extend_from_slice(job.claims);
    consts.extend([job.e, job.comp_z, job.periodic_claim]);
    let n = job.t * job.blowup;
    let mut out = vec![0u32; 4 * n];
    let done = shield_deep(
        &coeffs,
        job.combined.len() as u32,
        len as u32,
        &words(job.shifts.iter().copied()),
        &words(powers(job.sub, job.t / 2)),
        &words(powers(job.sub, job.t)),
        job.t as u32,
        job.blowup as u32,
        &words(job.comp.iter().flat_map(|v| [v.c0, v.c1])),
        &words(consts.iter().flat_map(|v| [v.c0, v.c1])),
        job.zks.len() as u32,
        &mut out,
    )
    .ok()?;
    if !done {
        return None;
    }
    let f = fields(&out);
    Some(f.chunks_exact(2).map(|p| Fp2::new(p[0], p[1])).collect())
}

/// The GPU from now on: the trace trees always, and the composition tree and the DEEP pass,
/// which move a few hundred megabytes each way, when `big` says the device has the memory.
/// Off puts every pass back on the cores.
#[wasm_bindgen]
pub fn use_gpu_committer(on: bool, big: bool) {
    clear_committer();
    if on {
        set_committer(on_gpu);
        if big {
            set_ext_committer(ext_on_gpu);
            set_deep(deep_on_gpu);
        }
    }
}

/// The cores' DEEP values for a small domain, by the prover's formula, which a GPU must match
/// before it is used. `consts` holds the quotients' constants as `shieldDeep` takes them.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn deep_reference(coeffs: &[u32], w: u32, len: u32, shifts: &[u32], log_t: u32, blowup: u32, comp: &[u32], consts: &[u32], window: u32) -> Vec<u32> {
    let (w, len, blowup, window) = (w as usize, len as usize, blowup as usize, window as usize);
    let t = 1usize << log_t;
    let all = fields(coeffs);
    let combined: Vec<Vec<Fp>> = (0..w).map(|j| all[j * len..(j + 1) * len].to_vec()).collect();
    let shifts = fields(shifts);
    let e2 = |v: &[u32]| -> Vec<Fp2> { fields(v).chunks_exact(2).map(|p| Fp2::new(p[0], p[1])).collect() };
    let comp = e2(comp);
    let k = e2(consts);
    let (zks, z, claims) = (&k[..window], k[window], &k[window + 1..2 * window + 1]);
    let (e, comp_z, pclaim) = (k[2 * window + 1], k[2 * window + 2], k[2 * window + 3]);
    let sub = root_of_unity(log_t);
    let mut deep = vec![Fp2::ZERO; t * blowup];
    for c in 0..blowup {
        let ev: Vec<Vec<Fp>> = combined.iter().map(|cf| lde_from_coeffs(cf, shifts[c], sub, t)).collect();
        for i in 0..t {
            let j = c + blowup * i;
            let x = Fp2::from_base(shifts[c] * sub.pow(i as u64));
            let mut acc = Fp2::ZERO;
            for (q, zk) in zks.iter().enumerate() {
                acc = acc + (Fp2::new(ev[2 * q][i], ev[2 * q + 1][i]) - claims[q]) * (x - *zk).inv();
            }
            let inv_z = (x - z).inv();
            acc = acc + e * ((comp[j] - comp_z) * inv_z);
            acc = acc + (Fp2::new(ev[2 * window][i], ev[2 * window + 1][i]) - pclaim) * inv_z;
            deep[j] = acc;
        }
    }
    words(deep.iter().flat_map(|v| [v.c0, v.c1]))
}

/// The coset root of a transform of 2^log_t points, as the reference and the GPU use it.
#[wasm_bindgen]
pub fn coset_root(log_t: u32) -> Vec<u32> {
    words(core::iter::once(root_of_unity(log_t)))
}

/// The cores' composition tree of `values`, from `cut` up, in the GPU's layout.
#[wasm_bindgen]
pub fn ext_reference(values: &[u32], cut: u32) -> Vec<u32> {
    let f = fields(values);
    let vals: Vec<Fp2> = f.chunks_exact(2).map(|p| Fp2::new(p[0], p[1])).collect();
    MerkleTree::commit_ext(&vals).layers()[cut as usize..]
        .iter()
        .flatten()
        .flat_map(|d| d.chunks_exact(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
        .collect()
}

/// The cores' tree for a commitment, from `cut` up, in the GPU's layout, which a GPU must match
/// before it is used.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn commit_reference(
    coeffs: &[u32],
    w: u32,
    len: u32,
    shifts: &[u32],
    sub: &[u32],
    t: u32,
    blowup: u32,
    cut: u32,
) -> Vec<u32> {
    let (w, len, t, blowup, cut) = (w as usize, len as usize, t as usize, blowup as usize, cut as usize);
    let all = fields(coeffs);
    let cols: Vec<Vec<Fp>> = (0..w).map(|j| all[j * len..(j + 1) * len].to_vec()).collect();
    let shifts = fields(shifts);
    let sub = fields(sub)[0];
    let mut digests = vec![[0u8; 32]; t * blowup];
    for c in 0..blowup {
        let ext: Vec<Vec<Fp>> = cols.iter().map(|cf| lde_from_coeffs(cf, shifts[c], sub, t)).collect();
        for i in 0..t {
            let row: Vec<Fp> = ext.iter().map(|col| col[i]).collect();
            digests[c + blowup * i] = hash_leaf_wide(&row);
        }
    }
    let tree = MerkleTree::from_leaf_digests(digests, hash_leaf_wide(&vec![Fp::ZERO; w]));
    tree.layers()[cut..]
        .iter()
        .flatten()
        .flat_map(|d| d.chunks_exact(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
        .collect()
}

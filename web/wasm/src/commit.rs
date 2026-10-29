//! The wide trace commitments on the GPU, where the worker found one that agrees with the cores.
//! The prover calls the committer from the thread that holds the proof; the worker's
//! `shieldCommit` blocks there until the GPU answers. The prover checks the tree it gets back
//! against its own arithmetic and proves again without it if it is wrong, so the GPU can cost
//! time and never a proof.

use nonos_stark::committer::{clear_committer, set_committer, WideCommit};
use nonos_stark::field::Fp;
use nonos_stark::merkle::{hash_leaf_wide, MerkleTree};
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

/// Commit on the GPU from now on, or on the cores again.
#[wasm_bindgen]
pub fn use_gpu_committer(on: bool) {
    if on {
        set_committer(on_gpu);
    } else {
        clear_committer();
    }
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

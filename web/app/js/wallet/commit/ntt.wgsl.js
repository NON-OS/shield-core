// The coset extension shared by the GPU's trace trees and its DEEP pass: each column's
// coefficients folded onto a transform's size with the coset's shift, then the radix-2 stages,
// over every column of a batch of cosets at once. The module that includes it declares the
// buffers it reads: coeffs, shifts, twiddles, work, and the parameters pr.

// prettier-ignore
export const PARAMS_WGSL = `
struct Params {
  w: u32,
  len_coeffs: u32,
  t: u32,
  log_t: u32,
  blowup: u32,
  batch: u32,
  c0: u32,
  len: u32,
  half: u32,
  step: u32,
  in_off: u32,
  out_off: u32,
  count: u32,
  window: u32,
  _b: u32,
  _c: u32,
}

`;

// prettier-ignore
export const NTT_WGSL = `
fn fpow(b: vec2<u32>, e: u32) -> vec2<u32> {
  var r = vec2<u32>(1u, 0u);
  var x = b;
  var k = e;
  while (k != 0u) {
    if ((k & 1u) != 0u) {
      r = fmul(r, x);
    }
    x = fmul(x, x);
    k = k >> 1u;
  }
  return r;
}

fn flat(id: vec3<u32>, groups: vec3<u32>) -> u32 {
  return id.x + id.y * groups.x * 64u;
}

// Coefficient j of each column lands on residue j mod t with weight shift^j, so one transform
// of size t evaluates the polynomial on the coset. Written in bit-reversed order for the stages.
@compute @workgroup_size(64)
fn fold(@builtin(global_invocation_id) id: vec3<u32>, @builtin(num_workgroups) groups: vec3<u32>) {
  let idx = flat(id, groups);
  if (idx >= pr.batch * pr.w * pr.t) {
    return;
  }
  let k = idx % pr.t;
  let col = (idx / pr.t) % pr.w;
  let ci = idx / (pr.t * pr.w);
  let shift = shifts[pr.c0 + ci];
  let step = fpow(shift, pr.t);
  var weight = fpow(shift, k);
  var acc = vec2<u32>(0u, 0u);
  var j = k;
  while (j < pr.len_coeffs) {
    acc = fadd(acc, fmul(coeffs[col * pr.len_coeffs + j], weight));
    weight = fmul(weight, step);
    j += pr.t;
  }
  let rev = reverseBits(k) >> (32u - pr.log_t);
  work[(ci * pr.w + col) * pr.t + rev] = acc;
}

// One radix-2 stage across every transform in the batch.
@compute @workgroup_size(64)
fn stage(@builtin(global_invocation_id) id: vec3<u32>, @builtin(num_workgroups) groups: vec3<u32>) {
  let idx = flat(id, groups);
  let pairs = pr.t / 2u;
  if (idx >= pr.batch * pr.w * pairs) {
    return;
  }
  let which = idx / pairs;
  let p = idx % pairs;
  let block = p / pr.half;
  let j = p % pr.half;
  let s = which * pr.t + block * pr.len + j;
  let u = work[s];
  let v = fmul(work[s + pr.half], twiddles[j * pr.step]);
  work[s] = fadd(u, v);
  work[s + pr.half] = fsub(u, v);
}

`;

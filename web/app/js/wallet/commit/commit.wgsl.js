// The trace commitment on the GPU: every column extended onto every coset, every row hashed into
// a wide leaf, and the tree built from 2^cut leaves up. Cosets go 2^cut at a time, so the leaves of
// one row across a batch are one subtree and fold straight to the level the prover keeps. The
// prover checks what comes back against its own arithmetic before it uses any of it.

import { FIELD_WGSL } from "./field.wgsl.js";
import { KECCAK_F_WGSL } from "./keccak.wgsl.js";

const words = (s) => {
  const bytes = new TextEncoder().encode(s);
  const out = [];
  for (let i = 0; i < bytes.length; i += 4) {
    out.push((bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24)) >>> 0);
  }
  return out;
};
const LEAF_TAG = words("NONOS-STARK-MERKLE-LEAF-WIDE");
const NODE_TAG = Array.from(new TextEncoder().encode("NONOS-STARK-MERKLE-NODE"));
const list = (xs) => xs.map((x) => `${x}u`).join(", ");

// prettier-ignore
export const COMMIT_WGSL = FIELD_WGSL + KECCAK_F_WGSL + `
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
  _a: u32,
  _b: u32,
  _c: u32,
}

@group(0) @binding(0) var<storage, read> coeffs: array<vec2<u32>>;
@group(0) @binding(1) var<storage, read> shifts: array<vec2<u32>>;
@group(0) @binding(2) var<storage, read> twiddles: array<vec2<u32>>;
@group(0) @binding(3) var<storage, read_write> work: array<vec2<u32>>;
@group(0) @binding(4) var<storage, read_write> tree: array<u32>;
@group(0) @binding(5) var<uniform> pr: Params;

const LEAF_TAG = array<u32, ${LEAF_TAG.length}>(${list(LEAF_TAG)});
const NODE_TAG = array<u32, ${NODE_TAG.length}>(${list(NODE_TAG)});

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

fn leaf(ci: u32, row: u32) -> array<u32, 8> {
  var st: array<vec2<u32>, 25>;
  let n_words = ${LEAF_TAG.length}u + 2u * pr.w;
  let pad_word = n_words;
  let blocks = (n_words * 4u) / 136u + 1u;
  for (var blk = 0u; blk < blocks; blk++) {
    for (var wi = 0u; wi < 34u; wi++) {
      let g = blk * 34u + wi;
      var v = 0u;
      if (g < ${LEAF_TAG.length}u) {
        v = LEAF_TAG[g];
      } else if (g < n_words) {
        let vi = (g - ${LEAF_TAG.length}u) / 2u;
        let val = work[(ci * pr.w + vi) * pr.t + row];
        v = select(val.y, val.x, ((g - ${LEAF_TAG.length}u) & 1u) == 0u);
      }
      if (g == pad_word) {
        v |= 1u;
      }
      if (blk == blocks - 1u && wi == 33u) {
        v |= 0x80000000u;
      }
      if ((wi & 1u) == 0u) {
        st[wi / 2u].x ^= v;
      } else {
        st[wi / 2u].y ^= v;
      }
    }
    keccak_f(&st);
  }
  return array<u32, 8>(st[0].x, st[0].y, st[1].x, st[1].y, st[2].x, st[2].y, st[3].x, st[3].y);
}

fn node_byte(k: u32, l: array<u32, 8>, r: array<u32, 8>) -> u32 {
  if (k < 23u) {
    return NODE_TAG[k];
  }
  if (k < 55u) {
    let b = k - 23u;
    return (l[b / 4u] >> (8u * (b % 4u))) & 0xffu;
  }
  if (k < 87u) {
    let b = k - 55u;
    return (r[b / 4u] >> (8u * (b % 4u))) & 0xffu;
  }
  if (k == 87u) {
    return 1u;
  }
  return 0u;
}

fn node(l: array<u32, 8>, r: array<u32, 8>) -> array<u32, 8> {
  var st: array<vec2<u32>, 25>;
  for (var wi = 0u; wi < 34u; wi++) {
    var v = 0u;
    for (var bb = 0u; bb < 4u; bb++) {
      v |= node_byte(wi * 4u + bb, l, r) << (8u * bb);
    }
    if (wi == 33u) {
      v |= 0x80000000u;
    }
    if ((wi & 1u) == 0u) {
      st[wi / 2u].x ^= v;
    } else {
      st[wi / 2u].y ^= v;
    }
  }
  keccak_f(&st);
  return array<u32, 8>(st[0].x, st[0].y, st[1].x, st[1].y, st[2].x, st[2].y, st[3].x, st[3].y);
}

// A row across the batch's cosets is 2^cut consecutive leaves: hash them and fold to one node.
@compute @workgroup_size(64)
fn leaves(@builtin(global_invocation_id) id: vec3<u32>, @builtin(num_workgroups) groups: vec3<u32>) {
  let row = flat(id, groups);
  if (row >= pr.t) {
    return;
  }
  var level: array<array<u32, 8>, 16>;
  for (var ci = 0u; ci < pr.batch; ci++) {
    level[ci] = leaf(ci, row);
  }
  var n = pr.batch;
  while (n > 1u) {
    for (var k = 0u; k < n / 2u; k++) {
      level[k] = node(level[2u * k], level[2u * k + 1u]);
    }
    n = n / 2u;
  }
  let at = pr.c0 / pr.batch + (pr.blowup / pr.batch) * row;
  for (var q = 0u; q < 8u; q++) {
    tree[8u * at + q] = level[0][q];
  }
}

// One level of the tree above the kept one.
@compute @workgroup_size(64)
fn level(@builtin(global_invocation_id) id: vec3<u32>, @builtin(num_workgroups) groups: vec3<u32>) {
  let k = flat(id, groups);
  if (k >= pr.count) {
    return;
  }
  var l: array<u32, 8>;
  var r: array<u32, 8>;
  for (var q = 0u; q < 8u; q++) {
    l[q] = tree[8u * (pr.in_off + 2u * k) + q];
    r[q] = tree[8u * (pr.in_off + 2u * k + 1u) + q];
  }
  let d = node(l, r);
  for (var q = 0u; q < 8u; q++) {
    tree[8u * (pr.out_off + k) + q] = d[q];
  }
}
`;

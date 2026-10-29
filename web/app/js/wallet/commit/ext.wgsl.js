// The composition tree on the GPU: each extension value hashed into a leaf as the prover's
// hash_leaf_ext does, 2^cut leaves folded to one node per invocation with a small stack, and the
// levels above built one dispatch each.

import { KECCAK_F_WGSL } from "./keccak.wgsl.js";
import { NODE_WGSL } from "./node.wgsl.js";

const TAG = Array.from(new TextEncoder().encode("NONOS-STARK-MERKLE-LEAF-EXT"));

// prettier-ignore
export const EXT_WGSL = KECCAK_F_WGSL + NODE_WGSL + `
struct Params {
  cut: u32,
  chunks: u32,
  in_off: u32,
  out_off: u32,
  count: u32,
  _a: u32,
  _b: u32,
  _c: u32,
}

@group(0) @binding(0) var<storage, read> values: array<vec2<u32>>;
@group(0) @binding(1) var<storage, read_write> tree: array<u32>;
@group(0) @binding(2) var<uniform> pr: Params;

const TAG = array<u32, ${TAG.length}>(${TAG.map((x) => `${x}u`).join(", ")});

fn leaf_byte(k: u32, c0: vec2<u32>, c1: vec2<u32>) -> u32 {
  if (k < ${TAG.length}u) {
    return TAG[k];
  }
  let b = k - ${TAG.length}u;
  if (b < 16u) {
    let w = array<u32, 4>(c0.x, c0.y, c1.x, c1.y);
    return (w[b / 4u] >> (8u * (b % 4u))) & 0xffu;
  }
  if (b == 16u) {
    return 1u;
  }
  return 0u;
}

fn leaf(j: u32) -> array<u32, 8> {
  let c0 = values[2u * j];
  let c1 = values[2u * j + 1u];
  var st: array<vec2<u32>, 25>;
  for (var wi = 0u; wi < 34u; wi++) {
    var v = 0u;
    for (var bb = 0u; bb < 4u; bb++) {
      v |= leaf_byte(wi * 4u + bb, c0, c1) << (8u * bb);
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

// The 2^cut leaves of chunk q, folded to their node with a stack of one digest a height.
@compute @workgroup_size(64)
fn chunks(@builtin(global_invocation_id) id: vec3<u32>, @builtin(num_workgroups) groups: vec3<u32>) {
  let q = id.x + id.y * groups.x * 64u;
  if (q >= pr.chunks) {
    return;
  }
  var stack: array<array<u32, 8>, 24>;
  var heights: array<u32, 24>;
  var top = 0u;
  let n = 1u << pr.cut;
  for (var k = 0u; k < n; k++) {
    var d = leaf(q * n + k);
    var h = 0u;
    while (top > 0u && heights[top - 1u] == h) {
      d = node(stack[top - 1u], d);
      top -= 1u;
      h += 1u;
    }
    stack[top] = d;
    heights[top] = h;
    top += 1u;
  }
  for (var w = 0u; w < 8u; w++) {
    tree[8u * q + w] = stack[0][w];
  }
}

@compute @workgroup_size(64)
fn level(@builtin(global_invocation_id) id: vec3<u32>, @builtin(num_workgroups) groups: vec3<u32>) {
  let k = id.x + id.y * groups.x * 64u;
  if (k >= pr.count) {
    return;
  }
  var l: array<u32, 8>;
  var r: array<u32, 8>;
  for (var w = 0u; w < 8u; w++) {
    l[w] = tree[8u * (pr.in_off + 2u * k) + w];
    r[w] = tree[8u * (pr.in_off + 2u * k + 1u) + w];
  }
  let d = node(l, r);
  for (var w = 0u; w < 8u; w++) {
    tree[8u * (pr.out_off + k) + w] = d[w];
  }
}
`;

// The Merkle node hash for WGSL: keccak256 of the node tag and the two children's 32 bytes, as
// the prover's own hash_node computes it. Needs KECCAK_F_WGSL before it.

const NODE_TAG = Array.from(new TextEncoder().encode("NONOS-STARK-MERKLE-NODE"));

// prettier-ignore
export const NODE_WGSL = `
const NODE_TAG = array<u32, ${NODE_TAG.length}>(${NODE_TAG.map((x) => `${x}u`).join(", ")});

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

`;

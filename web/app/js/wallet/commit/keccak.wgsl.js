// Keccak-f[1600] for WGSL, generated from the prover's own round constants and rho offsets. A
// lane is a vec2<u32>, low word first.

// prettier-ignore
export const KECCAK_F_WGSL = `
const RC = array<vec2<u32>, 24>(
  vec2<u32>(0x00000001u, 0x00000000u),
  vec2<u32>(0x00008082u, 0x00000000u),
  vec2<u32>(0x0000808au, 0x80000000u),
  vec2<u32>(0x80008000u, 0x80000000u),
  vec2<u32>(0x0000808bu, 0x00000000u),
  vec2<u32>(0x80000001u, 0x00000000u),
  vec2<u32>(0x80008081u, 0x80000000u),
  vec2<u32>(0x00008009u, 0x80000000u),
  vec2<u32>(0x0000008au, 0x00000000u),
  vec2<u32>(0x00000088u, 0x00000000u),
  vec2<u32>(0x80008009u, 0x00000000u),
  vec2<u32>(0x8000000au, 0x00000000u),
  vec2<u32>(0x8000808bu, 0x00000000u),
  vec2<u32>(0x0000008bu, 0x80000000u),
  vec2<u32>(0x00008089u, 0x80000000u),
  vec2<u32>(0x00008003u, 0x80000000u),
  vec2<u32>(0x00008002u, 0x80000000u),
  vec2<u32>(0x00000080u, 0x80000000u),
  vec2<u32>(0x0000800au, 0x00000000u),
  vec2<u32>(0x8000000au, 0x80000000u),
  vec2<u32>(0x80008081u, 0x80000000u),
  vec2<u32>(0x00008080u, 0x80000000u),
  vec2<u32>(0x80000001u, 0x00000000u),
  vec2<u32>(0x80008008u, 0x80000000u)
);

fn rotl_lo(x: vec2<u32>, n: u32) -> vec2<u32> {
  return vec2<u32>((x.x << n) | (x.y >> (32u - n)), (x.y << n) | (x.x >> (32u - n)));
}

fn rotl_hi(x: vec2<u32>, n: u32) -> vec2<u32> {
  return vec2<u32>((x.y << n) | (x.x >> (32u - n)), (x.x << n) | (x.y >> (32u - n)));
}

fn keccak_f(a: ptr<function, array<vec2<u32>, 25>>) {
  var b: array<vec2<u32>, 25>;
  for (var round = 0u; round < 24u; round++) {
    let c0 = (*a)[0] ^ (*a)[5] ^ (*a)[10] ^ (*a)[15] ^ (*a)[20];
    let c1 = (*a)[1] ^ (*a)[6] ^ (*a)[11] ^ (*a)[16] ^ (*a)[21];
    let c2 = (*a)[2] ^ (*a)[7] ^ (*a)[12] ^ (*a)[17] ^ (*a)[22];
    let c3 = (*a)[3] ^ (*a)[8] ^ (*a)[13] ^ (*a)[18] ^ (*a)[23];
    let c4 = (*a)[4] ^ (*a)[9] ^ (*a)[14] ^ (*a)[19] ^ (*a)[24];
    let d0 = c4 ^ rotl_lo(c1, 1u);
    let d1 = c0 ^ rotl_lo(c2, 1u);
    let d2 = c1 ^ rotl_lo(c3, 1u);
    let d3 = c2 ^ rotl_lo(c4, 1u);
    let d4 = c3 ^ rotl_lo(c0, 1u);
    for (var y = 0u; y < 25u; y += 5u) {
      (*a)[y] ^= d0;
      (*a)[y + 1u] ^= d1;
      (*a)[y + 2u] ^= d2;
      (*a)[y + 3u] ^= d3;
      (*a)[y + 4u] ^= d4;
    }
    b[0] = (*a)[0];
    b[10] = rotl_lo((*a)[1], 1u);
    b[20] = rotl_hi((*a)[2], 30u);
    b[5] = rotl_lo((*a)[3], 28u);
    b[15] = rotl_lo((*a)[4], 27u);
    b[16] = rotl_hi((*a)[5], 4u);
    b[1] = rotl_hi((*a)[6], 12u);
    b[11] = rotl_lo((*a)[7], 6u);
    b[21] = rotl_hi((*a)[8], 23u);
    b[6] = rotl_lo((*a)[9], 20u);
    b[7] = rotl_lo((*a)[10], 3u);
    b[17] = rotl_lo((*a)[11], 10u);
    b[2] = rotl_hi((*a)[12], 11u);
    b[12] = rotl_lo((*a)[13], 25u);
    b[22] = rotl_hi((*a)[14], 7u);
    b[23] = rotl_hi((*a)[15], 9u);
    b[8] = rotl_hi((*a)[16], 13u);
    b[18] = rotl_lo((*a)[17], 15u);
    b[3] = rotl_lo((*a)[18], 21u);
    b[13] = rotl_lo((*a)[19], 8u);
    b[14] = rotl_lo((*a)[20], 18u);
    b[24] = rotl_lo((*a)[21], 2u);
    b[9] = rotl_hi((*a)[22], 29u);
    b[19] = rotl_hi((*a)[23], 24u);
    b[4] = rotl_lo((*a)[24], 14u);
    for (var y = 0u; y < 25u; y += 5u) {
      (*a)[y] = b[y] ^ (~b[y + 1u] & b[y + 2u]);
      (*a)[y + 1u] = b[y + 1u] ^ (~b[y + 2u] & b[y + 3u]);
      (*a)[y + 2u] = b[y + 2u] ^ (~b[y + 3u] & b[y + 4u]);
      (*a)[y + 3u] = b[y + 3u] ^ (~b[y + 4u] & b[y]);
      (*a)[y + 4u] = b[y + 4u] ^ (~b[y] & b[y + 1u]);
    }
    (*a)[0] ^= RC[round];
  }
}
`;

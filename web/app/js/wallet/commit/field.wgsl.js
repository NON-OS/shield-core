// Goldilocks arithmetic for WGSL, which has no 64-bit integers: an element is a vec2<u32>, low
// word first, always canonical, below p = 2^64 - 2^32 + 1. Reduction uses 2^64 = 2^32 - 1 and
// 2^96 = -1 mod p, as the prover's own field does.

// prettier-ignore
export const FIELD_WGSL = `
const P = vec2<u32>(1u, 0xffffffffu);

fn ge64(a: vec2<u32>, b: vec2<u32>) -> bool {
  return a.y > b.y || (a.y == b.y && a.x >= b.x);
}

// a + b as 64 bits, and the carry out.
fn add64(a: vec2<u32>, b: vec2<u32>) -> vec3<u32> {
  let lo = a.x + b.x;
  let c0 = select(0u, 1u, lo < a.x);
  let hi1 = a.y + b.y;
  let c1 = select(0u, 1u, hi1 < a.y);
  let hi = hi1 + c0;
  let c2 = select(0u, 1u, hi < hi1);
  return vec3<u32>(lo, hi, c1 + c2);
}

// a - b as 64 bits, and the borrow out.
fn sub64(a: vec2<u32>, b: vec2<u32>) -> vec3<u32> {
  let lo = a.x - b.x;
  let b0 = select(0u, 1u, a.x < b.x);
  let hi1 = a.y - b.y;
  let b1 = select(0u, 1u, a.y < b.y);
  let hi = hi1 - b0;
  let b2 = select(0u, 1u, hi1 < b0);
  return vec3<u32>(lo, hi, b1 + b2);
}

fn fadd(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
  let s = add64(a, b);
  var r = s.xy;
  if (s.z != 0u) {
    // 2^64 = 2^32 - 1: add EPSILON, which cannot carry again here.
    r = add64(r, vec2<u32>(0xffffffffu, 0u)).xy;
  }
  if (ge64(r, P)) {
    r = sub64(r, P).xy;
  }
  return r;
}

fn fsub(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
  let d = sub64(a, b);
  if (d.z != 0u) {
    // Wrapped below zero: adding p is subtracting EPSILON mod 2^64.
    return sub64(d.xy, vec2<u32>(0xffffffffu, 0u)).xy;
  }
  return d.xy;
}

// The 64-bit product of two 32-bit words, from 16-bit halves.
fn mul32(a: u32, b: u32) -> vec2<u32> {
  let al = a & 0xffffu;
  let ah = a >> 16u;
  let bl = b & 0xffffu;
  let bh = b >> 16u;
  let ll = al * bl;
  let lh = al * bh;
  let hl = ah * bl;
  let hh = ah * bh;
  let mid = lh + hl;
  let mid_c = select(0u, 1u, mid < lh);
  let lo = ll + (mid << 16u);
  let lo_c = select(0u, 1u, lo < ll);
  let hi = hh + (mid >> 16u) + (mid_c << 16u) + lo_c;
  return vec2<u32>(lo, hi);
}

// Reduce lo + hi * 2^64 into [0, p), hi = (hi_lo, hi_hi).
fn reduce(lo: vec2<u32>, hi: vec2<u32>) -> vec2<u32> {
  let d = sub64(lo, vec2<u32>(hi.y, 0u));
  var t = d.xy;
  if (d.z != 0u) {
    t = sub64(t, vec2<u32>(0xffffffffu, 0u)).xy;
  }
  // hi_lo * (2^32 - 1) = hi_lo * 2^32 - hi_lo, never negative.
  let u = sub64(vec2<u32>(0u, hi.x), vec2<u32>(hi.x, 0u)).xy;
  let s = add64(t, u);
  var r = s.xy;
  if (s.z != 0u) {
    r = add64(r, vec2<u32>(0xffffffffu, 0u)).xy;
  }
  if (ge64(r, P)) {
    r = sub64(r, P).xy;
  }
  return r;
}

fn fmul(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
  let p00 = mul32(a.x, b.x);
  let p01 = mul32(a.x, b.y);
  let p10 = mul32(a.y, b.x);
  let p11 = mul32(a.y, b.y);
  // Words w1..w3 of the 128-bit product, with their carries.
  let m = add64(vec2<u32>(p00.y, 0u), vec2<u32>(p01.x, 0u));
  let m2 = add64(m.xy, vec2<u32>(p10.x, 0u));
  let w1 = m2.x;
  let carry1 = m2.y;
  let h = add64(vec2<u32>(p01.y, 0u), vec2<u32>(p10.y, 0u));
  let h2 = add64(h.xy, vec2<u32>(p11.x, 0u));
  let h3 = add64(h2.xy, vec2<u32>(carry1, 0u));
  let w2 = h3.x;
  let w3 = p11.y + h3.y;
  return reduce(vec2<u32>(p00.x, w1), vec2<u32>(w2, w3));
}
`;

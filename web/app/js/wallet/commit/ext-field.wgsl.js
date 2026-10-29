// The degree-2 extension Fp[X]/(X^2 - 7) for WGSL, as the prover's Fp2: an element is
// vec4<u32>, c0 then c1, each a canonical Goldilocks element low word first. Needs FIELD_WGSL.

// prettier-ignore
export const EXT_FIELD_WGSL = `
fn e2(c0: vec2<u32>, c1: vec2<u32>) -> vec4<u32> {
  return vec4<u32>(c0, c1);
}

fn e2add(a: vec4<u32>, b: vec4<u32>) -> vec4<u32> {
  return e2(fadd(a.xy, b.xy), fadd(a.zw, b.zw));
}

fn e2sub(a: vec4<u32>, b: vec4<u32>) -> vec4<u32> {
  return e2(fsub(a.xy, b.xy), fsub(a.zw, b.zw));
}

// (a0 + a1 X)(b0 + b1 X) = a0 b0 + 7 a1 b1 + (a0 b1 + a1 b0) X
fn e2mul(a: vec4<u32>, b: vec4<u32>) -> vec4<u32> {
  let a0b0 = fmul(a.xy, b.xy);
  let a1b1 = fmul(a.zw, b.zw);
  let seven = fmul(a1b1, vec2<u32>(7u, 0u));
  let cross = fadd(fmul(a.xy, b.zw), fmul(a.zw, b.xy));
  return e2(fadd(a0b0, seven), cross);
}

// The base field inverse, a^(p - 2), zero for zero.
fn finv(a: vec2<u32>) -> vec2<u32> {
  // p - 2 = 0xFFFFFFFE_FFFFFFFF: the low word all ones, the high word all ones but bit 0.
  var r = vec2<u32>(1u, 0u);
  var x = a;
  for (var i = 0u; i < 32u; i++) {
    r = fmul(r, x);
    x = fmul(x, x);
  }
  for (var i = 0u; i < 32u; i++) {
    if (i != 0u) {
      r = fmul(r, x);
    }
    x = fmul(x, x);
  }
  return r;
}

// 1 / (c0 + c1 X) = (c0 - c1 X) / (c0^2 - 7 c1^2), zero for zero.
fn e2inv(a: vec4<u32>) -> vec4<u32> {
  let norm = fsub(fmul(a.xy, a.xy), fmul(fmul(a.zw, a.zw), vec2<u32>(7u, 0u)));
  let n = finv(norm);
  return e2(fmul(a.xy, n), fmul(fsub(vec2<u32>(0u, 0u), a.zw), n));
}
`;

// The DEEP pass on the GPU, as the prover's preprocessed one computes it: the 2 (window + 1)
// combined polynomials extended onto a batch of cosets, then at every point the trace quotients
// for each window row, the composition quotient and the periodic quotient, summed in Fp2.

import { FIELD_WGSL } from "./field.wgsl.js";
import { EXT_FIELD_WGSL } from "./ext-field.wgsl.js";
import { NTT_WGSL, PARAMS_WGSL } from "./ntt.wgsl.js";

// prettier-ignore
export const DEEP_WGSL = FIELD_WGSL + EXT_FIELD_WGSL + PARAMS_WGSL + `
@group(0) @binding(0) var<storage, read> coeffs: array<vec2<u32>>;
@group(0) @binding(1) var<storage, read> shifts: array<vec2<u32>>;
@group(0) @binding(2) var<storage, read> twiddles: array<vec2<u32>>;
@group(0) @binding(3) var<storage, read_write> work: array<vec2<u32>>;
@group(0) @binding(4) var<storage, read_write> deep: array<vec4<u32>>;
@group(0) @binding(5) var<uniform> pr: Params;
@group(0) @binding(6) var<storage, read> comp: array<vec4<u32>>;
@group(0) @binding(7) var<storage, read> consts: array<vec4<u32>>;
@group(0) @binding(8) var<storage, read> powers: array<vec2<u32>>;
` + NTT_WGSL + `
// consts: z_k for each window row, then z, then the claim sum for each window row, then the
// composition's coefficient, its value at z, and the periodic claim sum.
@compute @workgroup_size(64)
fn points(@builtin(global_invocation_id) id: vec3<u32>, @builtin(num_workgroups) groups: vec3<u32>) {
  let idx = flat(id, groups);
  if (idx >= pr.batch * pr.t) {
    return;
  }
  let ci = idx / pr.t;
  let row = idx % pr.t;
  let c = pr.c0 + ci;
  let j = c + pr.blowup * row;
  let x = e2(fmul(shifts[c], powers[row]), vec2<u32>(0u, 0u));
  let win = pr.window;
  let ev = (ci * pr.w) * pr.t + row;
  var acc = vec4<u32>(0u, 0u, 0u, 0u);
  for (var k = 0u; k < win; k++) {
    let v = e2(work[ev + (2u * k) * pr.t], work[ev + (2u * k + 1u) * pr.t]);
    let inv = e2inv(e2sub(x, consts[k]));
    acc = e2add(acc, e2mul(e2sub(v, consts[win + 1u + k]), inv));
  }
  let inv_z = e2inv(e2sub(x, consts[win]));
  let e = consts[2u * win + 1u];
  let comp_z = consts[2u * win + 2u];
  let periodic_claim = consts[2u * win + 3u];
  acc = e2add(acc, e2mul(e, e2mul(e2sub(comp[j], comp_z), inv_z)));
  let pv = e2(work[ev + (2u * win) * pr.t], work[ev + (2u * win + 1u) * pr.t]);
  acc = e2add(acc, e2mul(e2sub(pv, periodic_claim), inv_z));
  deep[j] = acc;
}
`;

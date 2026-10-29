// Runs the commitment kernels: the coefficients, coset shifts and twiddles go up once, every
// batch of cosets is extended and hashed on the GPU, and only the tree from the kept level up
// comes back.

import { COMMIT_WGSL } from "./commit.wgsl.js";

const SLOT = 256;
const MAX_GROUPS = 65535;

export async function commitPipelines(device) {
  const module = device.createShaderModule({ code: COMMIT_WGSL });
  const S = GPUShaderStage.COMPUTE;
  const storage = (type) => ({ visibility: S, buffer: { type } });
  const layout = device.createBindGroupLayout({
    entries: [
      { binding: 0, ...storage("read-only-storage") },
      { binding: 1, ...storage("read-only-storage") },
      { binding: 2, ...storage("read-only-storage") },
      { binding: 3, ...storage("storage") },
      { binding: 4, ...storage("storage") },
      { binding: 5, visibility: S, buffer: { type: "uniform", hasDynamicOffset: true } },
    ],
  });
  const pipelineLayout = device.createPipelineLayout({ bindGroupLayouts: [layout] });
  const make = (entryPoint) =>
    device.createComputePipelineAsync({ layout: pipelineLayout, compute: { module, entryPoint } });
  const [fold, stage, leaves, level] = await Promise.all(
    ["fold", "stage", "leaves", "level"].map(make),
  );
  return { device, layout, fold, stage, leaves, level };
}

const groupsFor = (n) => {
  const groups = Math.ceil(n / 64);
  const x = Math.min(groups, MAX_GROUPS);
  return [x, Math.ceil(groups / x)];
};

/**
 * The tree of a wide commitment from level `cut` up, as eight words a digest, level by level.
 * `coeffs` holds `w` columns of `len` coefficients, low word first; `shifts` every coset's shift;
 * `twiddles` the powers of the coset root below `t / 2`.
 */
export async function gpuCommit(g, { coeffs, w, len, shifts, twiddles, t, blowup, cut }) {
  const { device } = g;
  const batch = 1 << cut;
  const logT = Math.log2(t);
  const kept = (t * blowup) >> cut;
  const B = GPUBufferUsage;
  const upload = (data) => {
    const buf = device.createBuffer({
      size: Math.max(16, data.byteLength),
      usage: B.STORAGE | B.COPY_DST,
    });
    device.queue.writeBuffer(buf, 0, data);
    return buf;
  };
  const coeffBuf = upload(coeffs);
  const shiftBuf = upload(shifts);
  const twBuf = upload(twiddles);
  const work = device.createBuffer({ size: batch * w * t * 8, usage: B.STORAGE });
  const treeWords = (2 * kept - 1) * 8;
  const tree = device.createBuffer({ size: treeWords * 4, usage: B.STORAGE | B.COPY_SRC });

  // Every dispatch's parameters, one 256-byte slot each.
  const slots = [];
  const slot = (fields) => {
    slots.push(fields);
    return (slots.length - 1) * SLOT;
  };
  const base = { w, len_coeffs: len, t, log_t: logT, blowup, batch };
  const order = [
    "w",
    "len_coeffs",
    "t",
    "log_t",
    "blowup",
    "batch",
    "c0",
    "len",
    "half",
    "step",
    "in_off",
    "out_off",
    "count",
  ];
  const stages = [];
  for (let l = 2; l <= t; l *= 2) stages.push(slot({ ...base, len: l, half: l / 2, step: t / l }));
  const batches = [];
  for (let c0 = 0; c0 < blowup; c0 += batch) batches.push(slot({ ...base, c0 }));
  const levels = [];
  for (let inOff = 0, count = kept / 2; count >= 1; count /= 2) {
    levels.push({ at: slot({ ...base, in_off: inOff, out_off: inOff + count * 2, count }), count });
    inOff += count * 2;
  }
  const params = new Uint32Array((slots.length * SLOT) / 4);
  slots.forEach((f, i) => order.forEach((k, j) => (params[(i * SLOT) / 4 + j] = f[k] ?? 0)));
  const paramBuf = device.createBuffer({ size: params.byteLength, usage: B.UNIFORM | B.COPY_DST });
  device.queue.writeBuffer(paramBuf, 0, params);

  const bind = device.createBindGroup({
    layout: g.layout,
    entries: [coeffBuf, shiftBuf, twBuf, work, tree]
      .map((buffer, binding) => ({ binding, resource: { buffer } }))
      .concat([{ binding: 5, resource: { buffer: paramBuf, size: SLOT } }]),
  });
  const run = (pass, pipeline, at, n) => {
    pass.setPipeline(pipeline);
    pass.setBindGroup(0, bind, [at]);
    pass.dispatchWorkgroups(...groupsFor(n));
  };

  for (const at of batches) {
    const enc = device.createCommandEncoder();
    const pass = enc.beginComputePass();
    run(pass, g.fold, at, batch * w * t);
    for (const s of stages) run(pass, g.stage, s, (batch * w * t) / 2);
    run(pass, g.leaves, at, t);
    pass.end();
    device.queue.submit([enc.finish()]);
  }
  const enc = device.createCommandEncoder();
  const pass = enc.beginComputePass();
  for (const l of levels) run(pass, g.level, l.at, l.count);
  pass.end();
  const read = device.createBuffer({ size: treeWords * 4, usage: B.MAP_READ | B.COPY_DST });
  enc.copyBufferToBuffer(tree, 0, read, 0, treeWords * 4);
  device.queue.submit([enc.finish()]);
  await read.mapAsync(GPUMapMode.READ);
  const out = new Uint32Array(read.getMappedRange().slice(0));
  read.unmap();
  for (const b of [coeffBuf, shiftBuf, twBuf, work, tree, read, paramBuf]) b.destroy();
  return out;
}

// Runs the DEEP kernels: the combined polynomials, shifts, twiddles, the domain's powers, the
// composition's values and the constants go up once; the DEEP values come back.

import { DEEP_WGSL } from "./deep.wgsl.js";

const SLOT = 256;
const MAX_GROUPS = 65535;
const BATCH = 16;
const ORDER = [
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
  "window",
];

export async function deepPipelines(device) {
  const module = device.createShaderModule({ code: DEEP_WGSL });
  const S = GPUShaderStage.COMPUTE;
  const entry = (binding, type) => ({ binding, visibility: S, buffer: { type } });
  const layout = device.createBindGroupLayout({
    entries: [
      entry(0, "read-only-storage"),
      entry(1, "read-only-storage"),
      entry(2, "read-only-storage"),
      entry(3, "storage"),
      entry(4, "storage"),
      { binding: 5, visibility: S, buffer: { type: "uniform", hasDynamicOffset: true } },
      entry(6, "read-only-storage"),
      entry(7, "read-only-storage"),
      entry(8, "read-only-storage"),
    ],
  });
  const pipelineLayout = device.createPipelineLayout({ bindGroupLayouts: [layout] });
  const make = (entryPoint) =>
    device.createComputePipelineAsync({ layout: pipelineLayout, compute: { module, entryPoint } });
  const [fold, stage, points] = await Promise.all(["fold", "stage", "points"].map(make));
  return { device, layout, fold, stage, points };
}

const groupsFor = (n) => {
  const groups = Math.ceil(n / 64);
  const x = Math.min(groups, MAX_GROUPS);
  return [x, Math.ceil(groups / x)];
};

/** The DEEP values over the whole domain, four words a value, into `out`. */
export async function gpuDeep(g, job, out) {
  const { coeffs, w, len, shifts, twiddles, powers, t, blowup, comp, consts, window } = job;
  const { device } = g;
  const n = t * blowup;
  const batch = Math.min(BATCH, blowup);
  const B = GPUBufferUsage;
  const upload = (data) => {
    const buf = device.createBuffer({
      size: Math.max(16, data.byteLength),
      usage: B.STORAGE | B.COPY_DST,
    });
    device.queue.writeBuffer(buf, 0, data);
    return buf;
  };
  const bufs = [coeffs, shifts, twiddles].map(upload);
  const work = device.createBuffer({ size: batch * w * t * 8, usage: B.STORAGE });
  const deep = device.createBuffer({ size: n * 16, usage: B.STORAGE | B.COPY_SRC });
  const [compBuf, constBuf, powerBuf] = [comp, consts, powers].map(upload);

  const slots = [];
  const slot = (f) => (slots.push(f), (slots.length - 1) * SLOT);
  const base = { w, len_coeffs: len, t, log_t: Math.log2(t), blowup, batch, window };
  const stages = [];
  for (let l = 2; l <= t; l *= 2) stages.push(slot({ ...base, len: l, half: l / 2, step: t / l }));
  const batches = [];
  for (let c0 = 0; c0 < blowup; c0 += batch) batches.push(slot({ ...base, c0 }));
  const params = new Uint32Array((slots.length * SLOT) / 4);
  slots.forEach((f, i) => ORDER.forEach((k, j) => (params[(i * SLOT) / 4 + j] = f[k] ?? 0)));
  const paramBuf = device.createBuffer({ size: params.byteLength, usage: B.UNIFORM | B.COPY_DST });
  device.queue.writeBuffer(paramBuf, 0, params);
  const bind = device.createBindGroup({
    layout: g.layout,
    entries: [...bufs, work, deep]
      .map((buffer, binding) => ({ binding, resource: { buffer } }))
      .concat([
        { binding: 5, resource: { buffer: paramBuf, size: SLOT } },
        { binding: 6, resource: { buffer: compBuf } },
        { binding: 7, resource: { buffer: constBuf } },
        { binding: 8, resource: { buffer: powerBuf } },
      ]),
  });
  const run = (pass, pipeline, at, count) => {
    pass.setPipeline(pipeline);
    pass.setBindGroup(0, bind, [at]);
    pass.dispatchWorkgroups(...groupsFor(count));
  };
  for (const at of batches) {
    const enc = device.createCommandEncoder();
    const pass = enc.beginComputePass();
    run(pass, g.fold, at, batch * w * t);
    for (const s of stages) run(pass, g.stage, s, (batch * w * t) / 2);
    run(pass, g.points, at, batch * t);
    pass.end();
    device.queue.submit([enc.finish()]);
  }
  const read = device.createBuffer({ size: n * 16, usage: B.MAP_READ | B.COPY_DST });
  const enc = device.createCommandEncoder();
  enc.copyBufferToBuffer(deep, 0, read, 0, n * 16);
  device.queue.submit([enc.finish()]);
  await read.mapAsync(GPUMapMode.READ);
  new Uint32Array(out).set(new Uint32Array(read.getMappedRange()));
  read.unmap();
  for (const b of [...bufs, work, deep, compBuf, constBuf, powerBuf, read, paramBuf]) b.destroy();
}

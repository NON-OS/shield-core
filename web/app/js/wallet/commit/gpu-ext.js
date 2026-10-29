// Runs the composition tree's kernels: the values go up once and the tree from level `cut` up
// comes back, as eight words a digest, level by level.

import { EXT_WGSL } from "./ext.wgsl.js";

const SLOT = 256;
const MAX_GROUPS = 65535;

export async function extPipelines(device) {
  const module = device.createShaderModule({ code: EXT_WGSL });
  const S = GPUShaderStage.COMPUTE;
  const layout = device.createBindGroupLayout({
    entries: [
      { binding: 0, visibility: S, buffer: { type: "read-only-storage" } },
      { binding: 1, visibility: S, buffer: { type: "storage" } },
      { binding: 2, visibility: S, buffer: { type: "uniform", hasDynamicOffset: true } },
    ],
  });
  const pipelineLayout = device.createPipelineLayout({ bindGroupLayouts: [layout] });
  const make = (entryPoint) =>
    device.createComputePipelineAsync({ layout: pipelineLayout, compute: { module, entryPoint } });
  const [chunks, level] = await Promise.all([make("chunks"), make("level")]);
  return { device, layout, chunks, level };
}

const groupsFor = (n) => {
  const groups = Math.ceil(n / 64);
  const x = Math.min(groups, MAX_GROUPS);
  return [x, Math.ceil(groups / x)];
};

/** The composition tree of `values` (two field elements a value, two words each) from `cut` up. */
export async function gpuExtTree(g, { values, cut }) {
  const { device } = g;
  const n = values.length / 4;
  const kept = n >> cut;
  const B = GPUBufferUsage;
  const valueBuf = device.createBuffer({ size: values.byteLength, usage: B.STORAGE | B.COPY_DST });
  device.queue.writeBuffer(valueBuf, 0, values);
  const treeWords = (2 * kept - 1) * 8;
  const tree = device.createBuffer({ size: treeWords * 4, usage: B.STORAGE | B.COPY_SRC });
  const slots = [[cut, kept, 0, 0, 0]];
  for (let inOff = 0, count = kept / 2; count >= 1; count /= 2) {
    slots.push([cut, kept, inOff, inOff + count * 2, count]);
    inOff += count * 2;
  }
  const params = new Uint32Array((slots.length * SLOT) / 4);
  slots.forEach((f, i) => params.set(f, (i * SLOT) / 4));
  const paramBuf = device.createBuffer({ size: params.byteLength, usage: B.UNIFORM | B.COPY_DST });
  device.queue.writeBuffer(paramBuf, 0, params);
  const bind = device.createBindGroup({
    layout: g.layout,
    entries: [
      { binding: 0, resource: { buffer: valueBuf } },
      { binding: 1, resource: { buffer: tree } },
      { binding: 2, resource: { buffer: paramBuf, size: SLOT } },
    ],
  });
  const enc = device.createCommandEncoder();
  const pass = enc.beginComputePass();
  pass.setPipeline(g.chunks);
  pass.setBindGroup(0, bind, [0]);
  pass.dispatchWorkgroups(...groupsFor(kept));
  pass.setPipeline(g.level);
  slots.slice(1).forEach((f, i) => {
    pass.setBindGroup(0, bind, [(i + 1) * SLOT]);
    pass.dispatchWorkgroups(...groupsFor(f[4]));
  });
  pass.end();
  const read = device.createBuffer({ size: treeWords * 4, usage: B.MAP_READ | B.COPY_DST });
  enc.copyBufferToBuffer(tree, 0, read, 0, treeWords * 4);
  device.queue.submit([enc.finish()]);
  await read.mapAsync(GPUMapMode.READ);
  const out = new Uint32Array(read.getMappedRange().slice(0));
  read.unmap();
  for (const b of [valueBuf, tree, read, paramBuf]) b.destroy();
  return out;
}

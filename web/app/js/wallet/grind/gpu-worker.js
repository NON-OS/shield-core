// The GPU's side of the grind. The wallet's worker hands it a keccak template and the work, and
// waits on a shared flag; this worker searches nonces on the GPU in blocks, lowest block first,
// and writes the smallest nonce found. The prover checks that nonce before it uses it.

import { KECCAK_WGSL } from "./keccak.wgsl.js";
import { commitPipelines, gpuCommit } from "../commit/gpu-commit.js";

const GROUP = 64;
const PER = 16;
// Blocks start small, so a short grind answers fast, and grow to the largest dispatch.
const FIRST_GROUPS = 64;
const GROUPS = 16384;
const NONE = 0xffffffff;
const size = (groups) => GROUP * PER * groups;

let gpu = null;
let shared = null;

async function setup() {
  const adapter = await navigator.gpu?.requestAdapter({ powerPreference: "high-performance" });
  if (!adapter) return null;
  const device = await adapter.requestDevice();
  const module = device.createShaderModule({ code: KECCAK_WGSL });
  const pipeline = await device.createComputePipelineAsync({
    layout: "auto",
    compute: { module, entryPoint: "main" },
  });
  const buffer = (size, usage) => device.createBuffer({ size, usage });
  const B = GPUBufferUsage;
  const template = buffer(200, B.STORAGE | B.COPY_DST);
  const params = buffer(16, B.UNIFORM | B.COPY_DST);
  const found = buffer(4, B.STORAGE | B.COPY_SRC | B.COPY_DST);
  const read = buffer(4, B.MAP_READ | B.COPY_DST);
  const bind = device.createBindGroup({
    layout: pipeline.getBindGroupLayout(0),
    entries: [template, params, found].map((b, i) => ({ binding: i, resource: { buffer: b } })),
  });
  const commit = await commitPipelines(device);
  const info = adapter.info ?? {};
  const software =
    adapter.isFallbackAdapter || /swiftshader|llvmpipe/i.test(info.description ?? "");
  return { device, pipeline, template, params, found, read, bind, software, commit };
}

// One block of nonces from `base`: the smallest offset meeting the work, or NONE.
async function block(g, bits, base, groups) {
  const { device } = g;
  device.queue.writeBuffer(g.params, 0, new Uint32Array([bits, base, PER, 0]));
  device.queue.writeBuffer(g.found, 0, new Uint32Array([NONE]));
  const enc = device.createCommandEncoder();
  const pass = enc.beginComputePass();
  pass.setPipeline(g.pipeline);
  pass.setBindGroup(0, g.bind);
  pass.dispatchWorkgroups(groups);
  pass.end();
  enc.copyBufferToBuffer(g.found, 0, g.read, 0, 4);
  device.queue.submit([enc.finish()]);
  await g.read.mapAsync(GPUMapMode.READ);
  const offset = new Uint32Array(g.read.getMappedRange())[0];
  g.read.unmap();
  return offset;
}

async function search(g, lanes, bits) {
  g.device.queue.writeBuffer(g.template, 0, lanes);
  let groups = FIRST_GROUPS;
  for (
    let base = 0;
    base + size(groups) <= 2 ** 32;
    base += size(groups), groups = Math.min(GROUPS, groups * 4)
  ) {
    const offset = await block(g, bits, base, groups);
    if (offset !== NONE) return base + offset;
  }
  return -1;
}

// Nonces a second, from one block that meets nothing.
async function rate(g) {
  g.device.queue.writeBuffer(g.template, 0, new Uint32Array(50));
  await block(g, 64, 0, GROUPS);
  const start = performance.now();
  await block(g, 64, 0, GROUPS);
  return size(GROUPS) / ((performance.now() - start) / 1000);
}

// The answer to request `id`, unless the prover thread gave up waiting for it.
function answer(id, nonce, ok) {
  const ctl = new Int32Array(shared, 0, 2);
  if (Atomics.load(ctl, 1) !== id) return;
  const out = new Uint32Array(shared, 8, 2);
  out[0] = nonce;
  out[1] = ok;
  Atomics.store(ctl, 0, 2);
  Atomics.notify(ctl, 0);
}

onmessage = async ({ data }) => {
  if (data.op === "setup") {
    try {
      gpu = await setup();
      shared = data.shared;
      // A software adapter is the CPU again, and timing one takes minutes; under test it is used
      // without timing.
      if (!gpu || (gpu.software && !data.force)) postMessage({ ok: false });
      else postMessage({ ok: true, rate: data.force ? Infinity : await rate(gpu) });
    } catch (e) {
      postMessage({ ok: false, why: String(e?.message ?? e) });
    }
    return;
  }
  if (data.op === "commit") {
    try {
      new Uint32Array(data.out).set(await gpuCommit(gpu.commit, data.job));
      answer(data.id, 0, 1);
    } catch {
      answer(data.id, 0, 0);
    }
    return;
  }
  if (data.op === "search") {
    try {
      const n = await search(gpu, data.lanes, data.bits);
      answer(data.id, n < 0 ? 0 : n, n < 0 ? 0 : 1);
    } catch {
      answer(data.id, 0, 0);
    }
  }
};

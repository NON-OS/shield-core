// The wallet worker's side of the GPU grind. The prover calls `shieldGrind` from inside a proof,
// which holds this thread, so the call hands the search to the GPU's worker and blocks on a shared
// flag until it answers. The GPU is used only where it is real hardware, gives the CPU's own
// answer on a test grind, and searches faster than this device's cores; otherwise the prover
// grinds as before.

const WAIT_MS = 120_000;

export async function startGpuGrind({ core, threads, force = false }) {
  if (typeof navigator === "undefined" || !navigator.gpu || threads < 1) return null;
  const shared = new SharedArrayBuffer(12);
  const ctl = new Int32Array(shared, 0, 1);
  const out = new Uint32Array(shared, 4, 2);
  const worker = new Worker(new URL("./gpu-worker.js", import.meta.url), { type: "module" });
  const ready = await new Promise((resolve) => {
    worker.onmessage = ({ data }) => resolve(data);
    worker.postMessage({ op: "setup", shared, force });
  });
  if (!ready.ok) return stop(worker);

  const search = (lanes, bits) => {
    Atomics.store(ctl, 0, 1);
    worker.postMessage({ op: "search", lanes: Uint32Array.from(lanes), bits });
    if (Atomics.wait(ctl, 0, 1, WAIT_MS) === "timed-out") return -1;
    return out[1] ? out[0] : -1;
  };

  // The CPU's answer on a test grind, and its pace on this device's threads. The test template
  // leaves the nonce's bytes clear, as a real one does.
  const lanes = Uint32Array.from({ length: 50 }, (_, i) => (i * 0x9e3779b9) >>> 0);
  lanes[8] &= 0xff;
  lanes[9] = 0;
  lanes[10] &= ~0xff;
  const start = performance.now();
  const reference = core.grind_reference(lanes, 16);
  const perThread = (reference + 1) / ((performance.now() - start) / 1000);
  // The threaded build hashes two nonces a permutation, about 1.7 times one at a time.
  const cpuRate = perThread * threads * 1.7;
  if (search(lanes, 16) !== reference) return stop(worker);
  if (ready.rate < 1.5 * cpuRate) return stop(worker);

  self.shieldGrind = (template, bits) => search(template, bits);
  core.use_gpu_grinder(true);
  return { gpuRate: ready.rate, cpuRate };
}

function stop(worker) {
  worker.terminate();
  return null;
}

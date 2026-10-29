// The wallet worker's side of the GPU grind. The prover calls `shieldGrind` from inside a proof,
// which holds this thread, so the call hands the search to the GPU's worker and blocks on a shared
// flag until it answers. The GPU is used only where it is real hardware, gives the CPU's own
// answer on a test grind, and searches faster than this device's cores; otherwise the prover
// grinds as before.

const WAIT_MS = 120_000;
const P = (1n << 64n) - (1n << 32n) + 1n;

const pack = (xs) => {
  const a = new Uint32Array(xs.length * 2);
  xs.forEach((v, i) => {
    a[2 * i] = Number(v & 0xffffffffn);
    a[2 * i + 1] = Number(v >> 32n);
  });
  return a;
};

const power = (b, e) => {
  let r = 1n;
  for (let x = b % P, k = e; k > 0n; k >>= 1n, x = (x * x) % P) if (k & 1n) r = (r * x) % P;
  return r;
};

export async function startGpuGrind({ core, threads, force = false }) {
  if (typeof navigator === "undefined" || !navigator.gpu || threads < 1) return null;
  // The flag the prover thread waits on, the request it waits for, and the answer: a nonce and
  // whether there is one.
  const shared = new SharedArrayBuffer(16);
  const ctl = new Int32Array(shared, 0, 2);
  const out = new Uint32Array(shared, 8, 2);
  const worker = new Worker(new URL("./gpu-worker.js", import.meta.url), { type: "module" });
  const ready = await new Promise((resolve) => {
    worker.onmessage = ({ data }) => resolve(data);
    worker.postMessage({ op: "setup", shared, force });
  });
  if (!ready.ok) return stop(worker);

  // One request at a time, each with its own number, so an answer that comes after its wait gave up
  // is dropped rather than read as the next one's. A GPU that once runs out the wait is not asked
  // again this session: the cores do the rest.
  let seq = 0;
  let gaveUp = false;
  const ask = (message, transfer = []) => {
    if (gaveUp) return false;
    const id = ++seq;
    Atomics.store(ctl, 1, id);
    Atomics.store(ctl, 0, 1);
    worker.postMessage({ ...message, id }, transfer);
    if (Atomics.wait(ctl, 0, 1, WAIT_MS) === "timed-out") {
      Atomics.store(ctl, 1, 0);
      gaveUp = true;
      return false;
    }
    return out[1] === 1;
  };
  const search = (lanes, bits) =>
    ask({ op: "search", lanes: Uint32Array.from(lanes), bits }) ? out[0] : -1;

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

  // The trace commitments, the other half of a proof's hashing, go to the same GPU once it gives
  // the cores' own tree for a small commitment.
  const commit = (coeffs, w, len, shifts, twiddles, t, blowup, cut) => {
    const result = new SharedArrayBuffer((2 * ((t * blowup) >> cut) - 1) * 8 * 4);
    const job = {
      coeffs: Uint32Array.from(coeffs),
      w,
      len,
      shifts: Uint32Array.from(shifts),
      twiddles: Uint32Array.from(twiddles),
      t,
      blowup,
      cut,
    };
    return ask({ op: "commit", job, out: result }) ? new Uint32Array(result).slice() : null;
  };
  const t = 16;
  const sub = power(7n, (P - 1n) / BigInt(t));
  let seed = 0x9e3779b97f4a7c15n;
  const next = () => {
    seed = (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
    return seed % P;
  };
  const job = {
    coeffs: pack(Array.from({ length: 3 * 40 }, next)),
    shifts: pack(Array.from({ length: 16 }, next)),
    twiddles: pack(Array.from({ length: t / 2 }, (_, k) => power(sub, BigInt(k)))),
  };
  const want = core.commit_reference(job.coeffs, 3, 40, job.shifts, pack([sub]), t, 16, 3);
  const got = commit(job.coeffs, 3, 40, job.shifts, job.twiddles, t, 16, 3);
  const committing =
    Boolean(got) && got.length === want.length && got.every((x, i) => x === want[i]);
  if (committing) {
    self.shieldCommit = commit;
    core.use_gpu_committer(true);
  }
  return { gpuRate: ready.rate, cpuRate, committing };
}

function stop(worker) {
  worker.terminate();
  return null;
}

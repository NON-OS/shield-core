// The bench's worker. Proving runs here because the thread pool waits on atomics, which a
// browser forbids on a page's main thread.

import init, * as nox from "./pkg/nox_shield_web.js";

const text = async (path) => (await fetch(path)).text();
const unhex = (s) => Uint8Array.from(s.trim().match(/../g), (b) => parseInt(b, 16));

onmessage = async ({ data: { threads, cache } }) => {
  try {
    const wasm = await init();
    nox.report_panics?.();
    if (threads > 0) await nox.initThreadPool(threads);
    const [request, seed, entropyHex] = await Promise.all(
      ["request.json", "seed.json", "entropy.hex"].map((f) => text(`./vector/${f}`)),
    );
    const top = cache ? new Uint8Array(await (await fetch("./periodic.top")).arrayBuffer()) : null;
    const start = performance.now();
    const proof = top
      ? nox.prove_with_cache(request, seed, unhex(entropyHex), top)
      : nox.prove(request, seed, unhex(entropyHex));
    const ms = performance.now() - start;
    postMessage({
      ok: true,
      threads,
      cache,
      ms,
      wasmBytes: wasm.memory.buffer.byteLength,
      root: nox.periodic_root(),
      proof,
    });
  } catch (e) {
    postMessage({ ok: false, error: String(e?.message ?? e) });
  }
};

// Runs one proof of the pinned vector in a worker and leaves the result on window.benchResult,
// for the Playwright driver to read. Parameters come from the query string: threads (0 for the
// one-thread package) and cache (1 to prove from the periodic cache).

const params = new URLSearchParams(location.search);
const threads = Number(params.get("threads") ?? 0);
const cache = params.get("cache") === "1";
const out = document.getElementById("out");

const worker = new Worker(new URL("./bench-worker.js", import.meta.url), { type: "module" });
worker.onmessage = ({ data }) => {
  window.benchResult = { isolated: globalThis.crossOriginIsolated, cores: navigator.hardwareConcurrency, ...data };
  out.textContent = JSON.stringify({ ...window.benchResult, proof: undefined }, null, 1);
};
worker.onerror = (e) => {
  window.benchResult = { error: String(e.message ?? e) };
  out.textContent = window.benchResult.error;
};
worker.postMessage({ threads, cache });

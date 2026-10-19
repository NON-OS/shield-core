// Whether this device can make a proof here, in this browser. A computer can: a proof needs about
// 1 GiB, which is what was measured in a desktop browser. A phone or tablet browser may stop the
// page long before that and give no warning, so a private send there waits for one timed proof of
// the pinned test vector. A timing that started and never finished means the browser ended the
// page, and private sends stay refused on this device; the native app or a computer can make them.

import { handheld } from "./form.js";

const STARTED = "proof-timing-started";
const MEASURED = "proof-timing";

export async function proving(store) {
  if (typeof WebAssembly !== "object") return { state: "unable" };
  const threads = globalThis.crossOriginIsolated ? navigator.hardwareConcurrency || 1 : 0;
  const measured = await store.meta(MEASURED);
  if (measured) return { state: "ready", threads, measured };
  if (await store.meta(STARTED)) return { state: "stopped", threads };
  if (!handheld()) return { state: "ready", threads };
  return { state: "unmeasured", threads };
}

proving.started = (store) => store.setMeta(STARTED, Date.now());
proving.finished = async (store, result) => {
  await store.setMeta(MEASURED, result);
  await store.setMeta(STARTED, null);
};

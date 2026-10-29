import { test } from "node:test";
import assert from "node:assert/strict";
import { begin, estimate, finish, loadPace, mark } from "./proof-progress.js";

const store = () => {
  const m = new Map();
  return { meta: async (k) => m.get(k), setMeta: async (k, v) => void m.set(k, v) };
};

test("before the prover reports, nothing is done and the network step is open", async () => {
  await loadPace(store(), null);
  begin({ network: true });
  const e = estimate();
  assert.equal(e.share, 0);
  assert.equal(e.left, null);
  assert.equal(e.steps[0].label, "Read the pool's state");
  assert.equal(e.steps[0].took, null);
});

test("the bar never passes the end of the running phase before it is reported", async () => {
  await loadPace(store(), { seconds: 10 });
  begin();
  mark("request");
  const e = estimate(Date.now() + 600_000);
  assert.ok(e.share < 0.02, `share ${e.share}`);
  assert.ok(e.left > 0);
});

test("a finished proof teaches the pace the next one is told by", async () => {
  const s = store();
  await loadPace(s, null);
  const real = Date.now;
  let clock = real();
  Date.now = () => (clock += 1000);
  begin();
  mark("request");
  for (const p of ["blinding", "region", "products", "periodic", "composition"]) mark(p);
  for (const p of ["composition-tree", "deep", "fri", "queries", "verified"]) mark(p);
  Date.now = real;
  await finish(s);
  const kept = await s.meta("proof-phases");
  assert.equal(kept.seconds, 10);
  assert.equal(kept.ends.fri, 0.8);
  assert.equal(kept.ends.request, 0);
  assert.equal(Object.keys(kept.ends).length, 11);
});

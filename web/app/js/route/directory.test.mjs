import { test } from "node:test";
import assert from "node:assert/strict";
import { draw, entryGateways } from "./directory.js";

const node = (id, hostname, wss_port, performance) => ({
  ed25519_identity_pubkey: id,
  entry: hostname ? { hostname, wss_port } : null,
  performance,
});

test("only gateways with a host, an allowed wss port and a good performance qualify", async () => {
  const listed = [
    node("a", "a.example", 9001, "0.99"),
    node("b", "b.example", 9001, "0.5"),
    node("c", null, 9001, "1.0"),
    node("d", "d.example", 9000, "1.0"),
    node("e", "e.example", 443, "0.95"),
  ];
  globalThis.fetch = async () => new Response(JSON.stringify({ nodes: { data: listed } }));
  const ids = (await entryGateways()).map((g) => g.id);
  assert.deepEqual(ids, ["a", "e"]);
});

test("a directory host that fails gives way to the next", async () => {
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    if (calls === 1) throw new Error("down");
    return new Response(JSON.stringify({ nodes: [node("a", "a.example", 9001, "1")] }));
  };
  assert.equal((await entryGateways()).length, 1);
  assert.equal(calls, 2);
});

test("a draw never returns a gateway that failed, and stops when none is left", () => {
  const all = [
    { id: "a", weight: 1 },
    { id: "b", weight: 1 },
  ];
  for (let i = 0; i < 50; i++) assert.equal(draw(all, new Set(["a"])).id, "b");
  assert.throws(() => draw(all, new Set(["a", "b"])), /no Nym gateway/);
});

test("a draw follows the weights", () => {
  const all = [
    { id: "heavy", weight: 9 },
    { id: "light", weight: 1 },
  ];
  let heavy = 0;
  for (let i = 0; i < 2000; i++) if (draw(all, new Set()).id === "heavy") heavy += 1;
  assert.ok(heavy > 1600 && heavy < 1990, `heavy drawn ${heavy} times of 2000`);
});

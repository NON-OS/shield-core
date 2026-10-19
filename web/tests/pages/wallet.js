// Drives the wallet worker the way the screens do, for the smoke test. The passkey's secret is
// stood in for by fixed test bytes, since this checks the core and its storage, not WebAuthn.

import { Wallet } from "../js/wallet/client.js";

const secret = () => new Uint8Array(32).fill(7);
const wrong = () => new Uint8Array(32).fill(9);

async function wallet() {
  const cache = new Uint8Array(await (await fetch("../periodic.top")).arrayBuffer());
  const w = new Wallet(new URL("../js/wallet/worker.js", import.meta.url));
  const stored = await w.start({ threads: navigator.hardwareConcurrency, cache });
  return { w, stored };
}

const step = new URLSearchParams(location.search).get("step");

async function run() {
  const { w, stored } = await wallet();
  if (step === "create") {
    await w.holdKey(secret());
    const words = await w.call("create");
    return {
      stored,
      words: words.length,
      receiving: (await w.call("receivingAddress")).slice(0, 5),
      public: await w.call("publicAddress"),
      balances: await w.call("publicBalances", "sepolia"),
      chain: await w.call("syncChain"),
    };
  }
  const refused = await w
    .holdKey(wrong())
    .then(() => w.call("unlock"))
    .then(
      () => "opened",
      (e) => e.kind + ":" + e.detail,
    );
  await w.holdKey(secret());
  await w.call("unlock");
  return {
    stored,
    refused,
    public: await w.call("publicAddress"),
    shielded: await w.call("balances"),
  };
}

run().then(
  (r) => (window.result = { ok: true, ...r }),
  (e) =>
    (window.result = {
      ok: false,
      error: String(e?.message ?? e),
      kind: e?.kind,
      detail: e?.detail,
    }),
);

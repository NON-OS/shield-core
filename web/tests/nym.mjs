// Reads through Nym and direct, in turn, from a release in headless Chromium: the success rate of
// each and the time each read took, median and 90th percentile. Each read is the public account's
// balances on Sepolia, the core's own request; the run ends with one read of the pool each way.
// When the mixnet fails a read past its retries the page asks, and this answers "Stay on Nym", so
// the read counts as failed and nothing goes direct.
//
//   node web/tests/nym.mjs <site dir> [reads] [--stand-in]
//
// --stand-in serves a mix-fetch that is the browser's own fetch, for a network that cannot reach
// Nym: it checks the bridge, the core's replies through it and the page's CSP for the worker, and
// says nothing about the mixnet.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { chromium } from "playwright";
import { serve } from "./journey/harness.mjs";
import { headers } from "../scripts/headers.mjs";

const [site, readsArg] = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const standIn = process.argv.includes("--stand-in");
const reads = Number(readsArg ?? 20);
const port = 8835;
const base = `http://localhost:${port}`;
const manifest = JSON.parse(readFileSync(join(site, "release-manifest.json"), "utf8"));
const dir = readdirSync(join(site, "r"))[0];
const page = (name) => readFileSync(new URL(`./pages/${name}`, import.meta.url));
const sent = { ...headers(manifest.connect, manifest.mixnet), "Cache-Control": "no-store" };

const server = await serve(site, port);
const browser = await chromium.launch({ executablePath: "/opt/pw-browsers/chromium" });
const context = await browser.newContext({ serviceWorkers: "block" });
const fulfil = (body, type) => (r) =>
  r.fulfill({ status: 200, body, headers: { ...sent, "Content-Type": type } });
const js = "text/javascript; charset=utf-8";
await context.route(`${base}/r/${dir}/route-test.html*`, fulfil(page("route.html"), "text/html"));
await context.route(`${base}/r/${dir}/route-test.js`, fulfil(page("route.js"), js));
if (standIn)
  await context.route(
    `${base}/r/${dir}/nym/mix-fetch.js`,
    fulfil(
      "export const setupMixTunnel = async () => {};\nexport const mixFetch = (url, init) => fetch(url, init);\n",
      js,
    ),
  );
const tab = await context.newPage();
let declined = 0;
const asked = tab.getByRole("alertdialog");
const answer = async () => {
  while (!(await tab.evaluate(() => Boolean(window.result)))) {
    if (await asked.count()) {
      await tab.getByRole("button", { name: "Stay on Nym", exact: true }).click();
      declined += 1;
    }
    await tab.waitForTimeout(500);
  }
};
await tab.goto(`${base}/r/${dir}/route-test.html?reads=${reads}`);
await answer();
const result = await tab.evaluate(() => window.result);
await browser.close();
server.kill();
if (!result.ok) throw new Error(result.error);

const quantile = (xs, q) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil(q * s.length) - 1)];
};
const sec = (ms) => (ms / 1000).toFixed(2);
console.log(`${standIn ? "stand-in for mix-fetch" : "Nym"}, gateway ${result.gateway || "none"}`);
const cold = result.runs.find((r) => r.cold);
console.log(
  `first read through Nym, with the tunnel's start: ${cold.ok ? "ok" : "failed"}, ${sec(cold.ms)} s`,
);
for (const name of ["nym", "direct"]) {
  const runs = result.runs.filter(
    (r) => r.route === name && !r.cold && r.method === "publicBalances",
  );
  const ok = runs.filter((r) => r.ok).map((r) => r.ms);
  const times = ok.length
    ? `, median ${sec(quantile(ok, 0.5))} s, p90 ${sec(quantile(ok, 0.9))} s`
    : "";
  console.log(`${name}: ${ok.length} of ${runs.length} reads${times}`);
}
for (const r of result.runs.filter((r) => r.method === "syncChain"))
  console.log(`pool read, ${r.route}: ${r.ok ? "ok" : "failed"}, ${sec(r.ms)} s`);
console.log(`the page asked ${declined} time(s); each was answered Stay on Nym`);

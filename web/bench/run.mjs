// Drives the bench in headless Chromium and prints one JSON line per run.
//
//   node web/bench/run.mjs <site dir> <threads> <cache 0|1> <proof out>
//
// <site dir> holds the bench files, pkg/, vector/ and periodic.top. Memory is read two ways: the
// wasm linear memory the worker reports, which only grows, and the resident set of every browser
// process, sampled from /proc, of which the renderer that runs the page and its workers is the
// one a phone would kill.

import { spawn } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { chromium } from "playwright";

const [site, threads, cache, proofOut] = process.argv.slice(2);
const port = 8790 + Number(threads);
const files = spawn(
  process.execPath,
  [new URL("../scripts/serve.mjs", import.meta.url).pathname, site, String(port)],
  {
    stdio: "ignore",
  },
);
await new Promise((r) => setTimeout(r, 500));

const server = await chromium.launchServer({
  executablePath: "/opt/pw-browsers/chromium",
  headless: true,
});
const root = server.process().pid;
const browser = await chromium.connect(server.wsEndpoint());

const children = (pid) => {
  const out = [];
  for (const d of readdirSync("/proc")) {
    if (!/^\d+$/.test(d)) continue;
    try {
      const ppid = Number(readFileSync(`/proc/${d}/stat`, "utf8").split(") ")[1].split(" ")[1]);
      if (ppid === pid) out.push(Number(d), ...children(Number(d)));
    } catch {
      // The process ended between the listing and the read, so it has no children to count.
      continue;
    }
  }
  return out;
};
const rss = (pid) => {
  try {
    const m = readFileSync(`/proc/${pid}/status`, "utf8").match(/VmRSS:\s+(\d+) kB/);
    return m ? Number(m[1]) * 1024 : 0;
  } catch {
    return 0;
  }
};
const isRenderer = (pid) => {
  try {
    return readFileSync(`/proc/${pid}/cmdline`, "utf8").includes("--type=renderer");
  } catch {
    return false;
  }
};

let peakTotal = 0;
let peakRenderer = 0;
const sampler = setInterval(() => {
  const pids = [root, ...children(root)];
  let total = 0;
  for (const p of pids) {
    const r = rss(p);
    total += r;
    if (isRenderer(p)) peakRenderer = Math.max(peakRenderer, r);
  }
  peakTotal = Math.max(peakTotal, total);
}, 250);

const page = await browser.newPage();
page.on("console", (m) => console.error(`console: ${m.text()}`));
const wall = Date.now();
await page.goto(`http://127.0.0.1:${port}/index.html?threads=${threads}&cache=${cache}`);
await page.waitForFunction(() => window.benchResult, null, {
  timeout: 30 * 60 * 1000,
  polling: 1000,
});
const result = await page.evaluate(() => window.benchResult);
clearInterval(sampler);
await browser.close();
await server.close();
files.kill();

if (result.proof) writeFileSync(proofOut, result.proof);
const mib = (b) => Math.round(b / 2 ** 20);
console.log(
  JSON.stringify({
    ok: result.ok,
    error: result.error,
    isolated: result.isolated,
    cores: result.cores,
    threads: result.threads,
    cache: result.cache,
    proveSeconds: result.ms && +(result.ms / 1000).toFixed(1),
    pageSeconds: +((Date.now() - wall) / 1000).toFixed(1),
    wasmMiB: result.wasmBytes && mib(result.wasmBytes),
    rendererPeakMiB: mib(peakRenderer),
    browserPeakMiB: mib(peakTotal),
    root: result.root,
  }),
);

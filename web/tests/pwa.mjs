// The installed app's promises, in headless Chromium: the worker takes the page, the page stays
// cross-origin isolated when it opens from the worker's cache, it opens with no network and says
// so, Chromium finds nothing that keeps it from being installed, and a new release shows "Update
// ready" and opens in one reload, never mixed with the old.
//
//   node web/tests/pwa.mjs <release dir> <newer release dir>

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { chromium } from "playwright";

const [first, second] = process.argv.slice(2);
const port = 8818;
const base = `http://localhost:${port}`;
const axe = readFileSync(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8");
const serve = (dir) =>
  spawn(
    process.execPath,
    [new URL("../scripts/serve.mjs", import.meta.url).pathname, dir, String(port)],
    { stdio: "ignore" },
  );
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const failures = [];
const expect = (ok, what) => {
  console.log(`${ok ? "ok" : "FAILED"}: ${what}`);
  if (!ok) failures.push(what);
};

let server = serve(first);
await wait(500);
const browser = await chromium.launch({
  executablePath: "/opt/pw-browsers/chromium",
  headless: true,
});
const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
const page = await context.newPage();
const version = () => page.evaluate(() => document.querySelector(".status")?.textContent ?? "");

await page.goto(`${base}/`);
await page.getByText("I understand").waitFor({ timeout: 120_000 });
await page.evaluate(() => navigator.serviceWorker.ready);
await page.reload();
await page.getByText("I understand").waitFor();
expect(
  await page.evaluate(() => Boolean(navigator.serviceWorker.controller)),
  "the worker controls the page",
);
expect(
  await page.evaluate(() => globalThis.crossOriginIsolated),
  "isolated when served from the worker",
);
const before = await version();

await context.setOffline(true);
await page.reload();
await page.getByText("I understand").waitFor();
expect(
  await page.evaluate(() => globalThis.crossOriginIsolated),
  "isolated offline, after a reload",
);
expect((await version()).includes("offline"), "the status line says offline");
await context.setOffline(false);

const cdp = await context.newCDPSession(page);
const { installabilityErrors } = await cdp.send("Page.getInstallabilityErrors");
expect(installabilityErrors.length === 0, `installable (${JSON.stringify(installabilityErrors)})`);
const { errors } = await cdp.send("Page.getAppManifest");
expect(errors.length === 0, `the manifest parses (${JSON.stringify(errors)})`);

await page.evaluate(axe);
await page.evaluate(() => Promise.all(document.getAnimations().map((a) => a.finished)));
const found = await page.evaluate(async () => (await window.axe.run()).violations.map((v) => v.id));
expect(found.length === 0, `axe clean when opened from the worker (${found.join(", ")})`);

if (second) {
  server.kill();
  await wait(300);
  server = serve(second);
  await wait(500);
  await page.evaluate(async () => (await navigator.serviceWorker.getRegistration())?.update());
  await page.getByText("Update ready.").waitFor({ timeout: 120_000 });
  expect((await version()) === before, "the old release keeps serving until the update is taken");
  await page.getByRole("button", { name: "Reload", exact: true }).click();
  await page.waitForEvent("load");
  await page.getByText("I understand").waitFor();
  const after = await version();
  expect(after !== before, `the new release opens after one reload (${before} to ${after})`);
}

await browser.close();
server.kill();
if (failures.length) process.exit(1);

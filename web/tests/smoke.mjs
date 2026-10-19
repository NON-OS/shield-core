// The wallet in headless Chromium: create a wallet, read the public account and the pool over the
// browser's own requests, then reload, refuse a wrong key and open with the right one.
//
//   node web/tests/smoke.mjs <site dir>
//
// <site dir> is the app with pkg/ and periodic.top, as web/scripts/build-site.mjs assembles it.

import { spawn } from "node:child_process";
import { chromium } from "playwright";

const site = process.argv[2];
const port = 8811;
const server = spawn(
  process.execPath,
  [new URL("../scripts/serve.mjs", import.meta.url).pathname, site, String(port)],
  { stdio: "ignore" },
);
await new Promise((r) => setTimeout(r, 500));
const browser = await chromium.launch({
  executablePath: "/opt/pw-browsers/chromium",
  headless: true,
});
const context = await browser.newContext();
const page = await context.newPage();
page.on("console", (m) => console.error(`console: ${m.text()}`));

const run = async (step) => {
  await page.goto(`http://127.0.0.1:${port}/tests/wallet.html?step=${step}`);
  await page.waitForFunction(() => window.result, null, { timeout: 10 * 60 * 1000 });
  return page.evaluate(() => window.result);
};

const created = await run("create");
console.log(JSON.stringify({ step: "create", ...created }));
const opened = await run("open");
console.log(JSON.stringify({ step: "open", ...opened }));
await browser.close();
server.kill();
process.exit(created.ok && opened.ok && opened.stored && opened.refused !== "opened" ? 0 : 1);

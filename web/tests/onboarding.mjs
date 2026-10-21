// The screens in headless Chromium at phone width, with a virtual passkey that has PRF: the
// first-use notice, a new wallet, its words, the public account and the pool read from Sepolia,
// both receive screens, every other screen, lock and unlock. On every screen axe must find
// nothing and the page must not scroll sideways. The first step is taken by keyboard alone.
//
//   node web/tests/onboarding.mjs <site dir>

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { chromium } from "playwright";
import { title } from "./title.mjs";

const site = process.argv[2];
const port = 8812;
const base = `http://localhost:${port}`;
const axe = readFileSync(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8");

const server = spawn(
  process.execPath,
  [new URL("../scripts/serve.mjs", import.meta.url).pathname, site, String(port)],
  {
    stdio: "ignore",
  },
);
// A test that stops early must not leave its port taken for the next run.
process.on("exit", () => server.kill());
await new Promise((r) => setTimeout(r, 500));
const browser = await chromium.launch({
  executablePath: "/opt/pw-browsers/chromium",
  headless: true,
});
const context = await browser.newContext({ viewport: { width: 375, height: 740 } });
const page = await context.newPage();
const errors = [];
page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
page.on("pageerror", (e) => errors.push(String(e)));

const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
    hasPrf: true,
  },
});

const failures = [];
const heading = (name) =>
  page.getByRole("heading", { level: 1, name: title(name) }).waitFor({ timeout: 10 * 60 * 1000 });
const click = (name) => page.getByRole("button", { name, exact: true }).click();

async function check(screen) {
  // Each screen fades in over 0.19 s, and axe would read its colours half faded.
  await page.evaluate(() =>
    Promise.all(
      document
        .getAnimations()
        .filter((a) => a.effect?.getTiming().iterations !== Infinity)
        .map((a) => a.finished),
    ),
  );
  await page.evaluate(axe);
  const found = await page.evaluate(async () =>
    (await window.axe.run()).violations.map((v) => `${v.id}: ${v.help}`),
  );
  const wide = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  if (found.length) failures.push(`${screen}: ${found.join("; ")}`);
  if (wide) failures.push(`${screen}: scrolls sideways at 375 px`);
  console.log(
    `${screen}: axe ${found.length ? found.join("; ") : "clean"}${wide ? ", too wide" : ""}`,
  );
}

await page.goto(`${base}/`);
await heading("Before you start");
await check("notice");
for (let i = 0; i < 30; i++) {
  await page.keyboard.press("Tab");
  if ((await page.evaluate(() => document.activeElement?.textContent)) === "I understand") break;
}
await page.keyboard.press("Enter");
await heading("NØNOS");
await check("welcome");
await click("Create a wallet");
await heading("Recovery phrase");
const words = await page.locator("ol.words li").count();
await check("phrase");
await click("I have written them down");
await heading("Wallet");
await check("wallet");
await click("Read again");
await page.getByText("Read from a public endpoint").waitFor({ timeout: 120_000 });
const eth = await page.locator(".coin-row .amount").first().textContent();
await click("Shield");
await heading("Shield");
await click("Read the pool");
await page
  .getByRole("button", { name: "Read the pool", exact: true })
  .waitFor({ timeout: 10 * 60 * 1000 });
await page
  .getByText(/Not read from the pool yet/)
  .waitFor({ state: "detached", timeout: 10 * 60 * 1000 });
await click("Details");
await page.getByText("Pool read at block").waitFor({ timeout: 10 * 60 * 1000 });
const block = await page.locator(".tile-row .value").first().textContent();
await check("shield");
await click("Receive");
await heading("Receive");
await page.locator("img.qr").waitFor();
const nox1 = await page.locator(".value-block .visually-hidden").textContent();
await check("receive");
await click("Receive at the 0x address");
await page.locator("img.qr").waitFor();
const zero = await page.locator(".value-block .visually-hidden").textContent();
await check("receive 0x");
await click("Back");
await heading("Wallet");

await click("Send");
await heading("Send");
await check("public send");
await click("Back");
await heading("Wallet");
await click("Shield");
await heading("Shield");
for (const [action, name] of [
  ["Deposit", "Deposit"],
  ["Send", "Send"],
  ["Withdraw", "Withdraw"],
]) {
  await click(action);
  await heading(name);
  await check(`shield ${name.toLowerCase()}`);
  await click("Back");
  await heading("Shield");
}
await click("Deposit");
await click("Deposit from another wallet instead");
await page.getByText("The EVM address you will send from").waitFor();
await check("deposit from another wallet");
await click("Back");
await heading("Deposit");
await click("Back");
await heading("Shield");
await click("Time a proof in this browser");
await heading("Measure");
await check("measure");
await click("Back");
await heading("Settings");
for (const [link, name] of [
  ["Recovery words and keys", "Keys"],
  ["Check this release", "Check this release"],
  ["Licences", "Licences"],
  ["What the web version trusts", "Before you start"],
]) {
  await click(link);
  await heading(name);
  if (name === "Licences") await page.locator(".licences").first().waitFor();
  await check(name.toLowerCase());
  await click("Back");
  await heading("Settings");
}
await check("settings");
await click("Destroy this wallet");
await page.getByRole("button", { name: "Keep this wallet" }).waitFor();
await check("destroy");
await click("Keep this wallet");
await heading("Settings");
await click("Back");
await heading("Wallet");
await page.getByRole("button", { name: /^Account 1/ }).click();
await heading("Accounts");
await check("accounts");
await click("Back");
await heading("Wallet");
await click("Settings");
await click("Lock now");
await heading("Locked");
await check("locked");
await click("Unlock");
await heading("Wallet");

console.log(
  JSON.stringify({
    words,
    eth,
    poolBlock: block,
    nox1: `${nox1.slice(0, 8)}…`,
    nox1Length: nox1.length,
    publicAddress: zero,
  }),
);
if (errors.length) failures.push(`console errors: ${errors.join(" | ")}`);
await browser.close();
server.kill();
if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}

// The screens in headless Chromium at phone width, with a virtual passkey that has PRF: the
// first-use warning, a new wallet, its words, the public account and the pool read from Sepolia,
// both receive screens, lock and unlock. On every screen axe must find nothing and the page must
// not scroll sideways.
//
//   node web/tests/onboarding.mjs <site dir>

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { chromium } from "playwright";

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
  page.getByRole("heading", { level: 1, name }).waitFor({ timeout: 10 * 60 * 1000 });
const click = (name) => page.getByRole("button", { name, exact: true }).click();

async function check(screen) {
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
await check("warning");
// The first step by keyboard alone: Tab until the button has focus, then Enter.
for (let i = 0; i < 20; i++) {
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
const eth = await page.locator(".balance .amount").first().textContent();
await click("Shield");
await heading("Shield");
await click("Read the pool");
await page.getByText("pool read at block").waitFor({ timeout: 10 * 60 * 1000 });
const block = await page.locator("dd").first().textContent();
await check("shield");
await click("Receive");
await heading("Receive");
await page.locator("img.qr").waitFor();
const nox1 = await page.locator(".address").textContent();
await check("receive");
await click("Receive at the 0x address");
await page.locator("img.qr").waitFor();
const zero = await page.locator(".address").textContent();
await check("receive 0x");
await click("Back");
await heading("Wallet");
await click("Settings");
await heading("Settings");
await check("settings");
await page.getByRole("button", { name: "Lock now" }).click();
await heading("Locked");
await check("locked");
await click("Unlock");
await heading("Wallet");

// Every other screen, for axe and the width, without moving anything.
const visit = async (from, button, title, back = "Back") => {
  await click(from);
  if (button) await click(button);
  await heading(title);
  await check(title.toLowerCase());
  await click(back);
};
await click("Send");
await heading("Send");
await check("public send");
await click("Back");
await heading("Wallet");
await visit("Shield", "Deposit", "Deposit");
await heading("Shield");
await click("Send");
await heading("Send");
await check("private send");
await click("Back");
await click("Withdraw");
await heading("Withdraw");
await check("withdraw");
await click("Back");
await heading("Shield");
await click("Back");
await heading("Wallet");
for (const [link, title] of [
  ["Recovery words and keys", "Keys"],
  ["Time a proof in this browser", "Time a proof"],
  ["Check this release", "Check this release"],
  ["Licences", "Licences"],
]) {
  await click("Settings");
  await page.getByRole("button", { name: link }).click();
  await heading(title);
  await check(title.toLowerCase());
  await click("Back");
  await heading("Settings");
  await click("Back");
  await heading("Wallet");
}
await page.getByRole("button", { name: /^Account 1/ }).click();
await heading("Accounts");
await check("accounts");
await click("Back");
await heading("Wallet");
await click("Settings");
await page.getByRole("button", { name: "Destroy this wallet" }).click();
await heading("Destroy this wallet");
await check("destroy");
await click("Keep this wallet");
await heading("Settings");

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

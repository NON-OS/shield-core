// A wallet in headless Chromium at phone width, with a virtual passkey that has PRF. A wallet is
// made once and its recovery words kept in a file the caller names, outside the repository and
// readable by its owner only; every later run restores it from them. The words are never printed.

import { spawn } from "node:child_process";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { chromium } from "playwright";
import { title } from "../title.mjs";

export async function serve(site, port) {
  const script = new URL("../../scripts/serve.mjs", import.meta.url).pathname;
  const server = spawn(process.execPath, [script, site, String(port)], { stdio: "ignore" });
  await new Promise((r) => setTimeout(r, 500));
  return server;
}

export async function open(browser, base, wordsFile) {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: base });
  const page = await context.newPage();
  // Every failure the page shows, kept, since locking clears the banner before a step times out.
  await page.addInitScript(() => {
    window.failures = [];
    new MutationObserver(() => {
      for (const el of document.querySelectorAll("[role=alert]")) {
        const text = el.textContent;
        if (text && window.failures.at(-1) !== text) window.failures.push(text);
      }
    }).observe(document, { childList: true, subtree: true, characterData: true });
  });
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
  const w = {
    page,
    heading: (name, timeout = 30 * 60 * 1000) =>
      page.getByRole("heading", { level: 1, name: title(name) }).waitFor({ timeout }),
    click: (name) => page.getByRole("button", { name, exact: true }).click(),
    fill: (label, value) => page.getByLabel(label, { exact: true }).fill(value),
    text: (value, timeout = 30 * 60 * 1000) => page.getByText(value).first().waitFor({ timeout }),
    // Bring this wallet's page to the front, and unlock it if it locked while another page was in
    // front, as it does when hidden.
    ready: async () => {
      await page.bringToFront();
      if (await page.getByRole("heading", { level: 1, name: title("Locked") }).count()) {
        await page.getByRole("button", { name: "Unlock", exact: true }).click();
        await page
          .getByRole("heading", { level: 1, name: title("Wallet") })
          .waitFor({ timeout: 120_000 });
      }
    },
    // What the screen shows, for the log when a step stops.
    seen: async () =>
      `${await page
        .locator("h1")
        .textContent()
        .catch(() => "")} | ${await page
        .getByRole("alert")
        .textContent()
        .catch(() => "no failure shown")} | failures so far: ${await page
        .evaluate(() => window.failures.join(" / "))
        .catch(() => "")}`,
  };
  await page.goto(`${base}/`);
  await w.heading("Before you start");
  await w.click("I understand");
  await w.heading("NØNOS");
  if (existsSync(wordsFile)) {
    await w.click("Restore from a phrase");
    await w.heading("Restore a wallet");
    await page.getByLabel("Recovery phrase").fill(readFileSync(wordsFile, "utf8").trim());
    await w.click("Restore");
  } else {
    await w.click("Create a wallet");
    await w.heading("Recovery phrase");
    const words = await page.locator("ol.words li").allTextContents();
    writeFileSync(wordsFile, words.map((t) => t.replace(/^\d+\.\s*/, "")).join(" "), {
      mode: 0o600,
    });
    chmodSync(wordsFile, 0o600);
    await w.click("I have written them down");
  }
  await w.heading("Wallet");
  return w;
}

export const browser = () =>
  chromium.launch({ executablePath: "/opt/pw-browsers/chromium", headless: true });

// What the page does on the devices it must treat with care, in headless Chromium:
//
// - a passkey without PRF gets a refusal and no wallet is made;
// - on a phone a private send is refused until a test proof has finished here, then allowed;
// - a test proof that started and never finished, as when a phone browser ends the page, keeps
//   private sends refused on that device;
// - the recovery words, a second account and destroying the wallet, from Settings.
//
//   node web/tests/devices.mjs <site dir>

import { spawn } from "node:child_process";
import { chromium, devices } from "playwright";

const site = process.argv[2];
const port = 8815;
const base = `http://localhost:${port}`;
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
const failures = [];
const expect = (ok, what) => {
  console.log(`${ok ? "ok" : "FAILED"}: ${what}`);
  if (!ok) failures.push(what);
};

async function device(options, prf = true) {
  const context = await browser.newContext(options);
  const page = await context.newPage();
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
      hasPrf: prf,
    },
  });
  const heading = (name) =>
    page.getByRole("heading", { level: 1, name }).waitFor({ timeout: 15 * 60 * 1000 });
  const click = (name) => page.getByRole("button", { name, exact: true }).click();
  await page.goto(`${base}/`);
  await heading("Before you start");
  await click("I understand");
  await heading("NØNOS");
  return { context, page, heading, click };
}

{
  const d = await device({ viewport: { width: 390, height: 844 } }, false);
  await d.click("Create a wallet");
  await d.page.getByRole("alert").waitFor();
  const said = await d.page.getByRole("alert").textContent();
  expect(said.includes("cannot derive a secret"), "a passkey without PRF is refused");
  expect(
    !(await d.page.getByRole("heading", { name: "Recovery phrase" }).count()),
    "no wallet is made without PRF",
  );
  await d.context.close();
}

{
  const d = await device({ ...devices["iPhone 13"], defaultBrowserType: undefined });
  await d.click("Create a wallet");
  await d.heading("Recovery phrase");
  await d.click("I have written them down");
  await d.heading("Wallet");
  await d.click("Shield");
  await d.heading("Shield");
  await d.click("Send");
  await d.heading("Send");
  expect(
    await d.page.getByText("This device has not made a proof yet.").isVisible(),
    "a phone is refused before a test proof",
  );
  expect(
    !(await d.page.getByRole("button", { name: "Prove and seal" }).count()),
    "a phone has no Prove button before a test proof",
  );
  await d.click("Time a test proof");
  await d.heading("Time a proof");
  await d.click("Time one proof");
  await d.page.getByText("This device can prove.").waitFor({ timeout: 15 * 60 * 1000 });
  const seconds = await d.page.locator("dd").first().textContent();
  console.log(`test proof on the phone profile: ${seconds}`);
  await d.click("Back");
  await d.heading("Settings");
  await d.click("Back");
  await d.heading("Wallet");
  await d.click("Shield");
  await d.click("Send");
  await d.heading("Send");
  expect(
    await d.page.getByRole("button", { name: "Prove and seal" }).isVisible(),
    "a phone that finished a test proof may send",
  );

  // A proof that started and never finished: the mark is set and the page reloads, as when a
  // phone browser ends it.
  await d.page.evaluate(async () => {
    const { openStore } = await import(
      document.querySelector("script[type=module]").src.replace("app.js", "wallet/store.js")
    );
    const store = await openStore();
    await store.setMeta("proof-timing", null);
    await store.setMeta("proof-timing-started", Date.now());
  });
  await d.page.reload();
  await d.heading("Locked");
  await d.click("Unlock");
  await d.heading("Wallet");
  await d.click("Shield");
  await d.click("Send");
  await d.heading("Send");
  expect(
    await d.page.getByText("This device could not finish a test proof.").isVisible(),
    "a phone that could not finish stays refused",
  );
  expect(
    await d.page.getByText("NØNOS app or a computer").isVisible(),
    "the refusal points to the app or a computer",
  );

  await d.click("Back");
  await d.click("Back");
  await d.heading("Wallet");
  await d.click("Settings");
  await d.click("Recovery words and keys");
  await d.heading("Keys");
  await d.click("Show the recovery words");
  await d.page.locator("ol.words li").first().waitFor();
  expect(
    (await d.page.locator("ol.words li").count()) === 24,
    "the recovery words show after the passkey",
  );
  await d.click("Hide and go back");
  await d.heading("Settings");
  await d.click("Back");
  await d.heading("Wallet");
  await d.page.getByRole("button", { name: /^Account 1/ }).click();
  await d.heading("Accounts");
  await d.click("Add an account");
  await d.page.getByRole("button", { name: /^Account 2/ }).waitFor();
  expect(true, "a second account is added");
  await d.click("Back");
  await d.click("Settings");
  await d.click("Destroy this wallet");
  await d.heading("Destroy this wallet");
  await d.click("Destroy it");
  await d.heading("NØNOS");
  await d.page.reload();
  await d.heading("Before you start");
  expect(true, "a destroyed wallet leaves nothing to unlock");
  await d.context.close();
}

await browser.close();
server.kill();
if (failures.length) process.exit(1);

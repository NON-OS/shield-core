// The TESTING.md journey on Sepolia, through the screens, as a user takes it. Wallet A is funded
// with Sepolia ETH; it pays wallet B some ETH in public for gas, deposits, sends to B privately,
// and B withdraws to a fresh address of its own. Every spend is settled from the spender's public
// account, since a browser cannot reach the landers. Only public facts are printed.
//
//   node web/tests/journey/run.mjs <site dir> <words A> <words B> <step>
//
// <step> is gas, deposit, transfer or withdraw, in that order; each needs the one before it to
// have landed, and the transfer needs the deposit's root, which the pool commits every 5 minutes.

import { browser, open, serve } from "./harness.mjs";

const [site, wordsA, wordsB, step] = process.argv.slice(2);
const port = 8821;
const base = `http://localhost:${port}`;
const server = await serve(site, port);
const b = await browser();
const say = (fact) => console.log(`${new Date().toISOString()} ${step}: ${fact}`);

async function publicAddress(w) {
  await w.click("Receive");
  await w.heading("Receive");
  const nox1 = await w.page.locator(".value-block .visually-hidden").textContent();
  await w.click("Receive at the 0x address");
  const zero = await w.page.locator(".value-block .visually-hidden").filter({ hasText: /^0x/ });
  await zero.waitFor();
  const address = await zero.textContent();
  await w.click("Back");
  await w.heading("Wallet");
  return { nox1, address };
}

async function readPool(w) {
  await w.click("Shield");
  await w.heading("Shield");
  await w.click("Read the pool");
  // The row reads "Reading the pool" while the read runs, and its name again once it is done.
  await w.page
    .getByRole("button", { name: "Read the pool", exact: true })
    .waitFor({ timeout: 30 * 60 * 1000 });
  if (await w.page.getByRole("button", { name: "Details", exact: true }).count())
    await w.click("Details");
  await w.text("Pool read at block");
  const eth = await w.page.locator(".coin-row .amount").nth(1).textContent();
  const block = await w.page.locator(".tile-row .value").first().textContent();
  say(`pool read at block ${block}, ETH shielded ${eth}`);
  return eth;
}

async function mined(w, line) {
  await w.page
    .getByText(line)
    .first()
    .waitFor({ timeout: 40 * 60 * 1000 });
}

async function spend(w, { withdraw, to, amount }) {
  await w.click(withdraw ? "Withdraw" : "Send");
  await w.heading(withdraw ? "Withdraw" : "Send");
  await w.page.locator("#coin").selectOption("eth");
  if (to) await w.page.getByLabel(withdraw ? "To EVM address" : "To wallet address").fill(to);
  else
    await w.page.waitForFunction(() =>
      document.querySelectorAll("input")[0]?.value.startsWith("0x"),
    );
  const target = await w.page.locator("input").first().inputValue();
  await w.page.locator("input").nth(1).fill(amount);
  const started = Date.now();
  await w.click("Prove and seal");
  const next = await Promise.race([
    w.page
      .getByText("These notes are still new.")
      .waitFor({ timeout: 30 * 60 * 1000 })
      .then(() => "early"),
    w.page
      .getByText("Proved and sealed in this browser.")
      .waitFor({ timeout: 30 * 60 * 1000 })
      .then(() => "proved"),
  ]);
  if (next === "early") {
    say("the notes are new, going early as TESTING.md says for a small pool");
    await w.page.getByLabel("Type EARLY to send now anyway").fill("EARLY");
    await w.click("Send now anyway");
    await w.page
      .getByText("Proved and sealed in this browser.")
      .waitFor({ timeout: 30 * 60 * 1000 });
  }
  say(
    `proved in ${Math.round((Date.now() - started) / 1000)} s, including the request for the pool`,
  );
  await w.click("Settle it yourself");
  await w.page
    .getByRole("button", { name: "Confirm and settle" })
    .waitFor({ timeout: 10 * 60 * 1000 });
  await w.click("Confirm and settle");
  await w.text("Settling on the pool.");
  const hash = await w.page.locator(".value-block .visually-hidden").last().textContent();
  say(`settlement ${hash}`);
  await mined(w, "Settled on the pool.");
  say("settled on the pool");
  return target;
}

const a = await open(b, base, wordsA);
const A = await publicAddress(a);
say(`wallet A ${A.address}`);

if (step === "gas") {
  const w = await open(b, base, wordsB);
  const B = await publicAddress(w);
  await a.click("Send");
  await a.heading("Send");
  await a.page.locator("#coin").selectOption("eth");
  await a.fill("To 0x address", B.address);
  await a.fill("Amount in ETH", "0.01");
  await a.click("Review");
  await a.click("Confirm and send");
  await a.text("Transaction");
  say(`public send to B ${await a.page.locator(".value-block .visually-hidden").textContent()}`);
  await mined(a, "Sent and mined.");
  say("mined");
}

if (step === "deposit") {
  await readPool(a);
  await a.click("Deposit");
  await a.heading("Deposit");
  await a.page.locator("#coin").selectOption("eth");
  await a.page.locator("input").first().fill("0.05");
  await a.click("Review");
  await a.text("the note holds");
  say(`note holds ${await a.page.locator("dd").nth(3).textContent()}`);
  await a.click("Confirm and shield");
  await a.text("Deposit sent. Waiting for a block.");
  say(`deposit ${await a.page.locator(".value-block .visually-hidden").textContent()}`);
  await mined(a, "Shielded.");
  say("shielded");
}

if (step === "transfer") {
  const w = await open(b, base, wordsB);
  const B = await publicAddress(w);
  await readPool(a);
  await spend(a, { withdraw: false, to: B.nox1, amount: "0.02" });
  say(`B reads the pool, ETH shielded ${await readPool(w)}`);
}

if (step === "withdraw") {
  const w = await open(b, base, wordsB);
  await readPool(w);
  const to = await spend(w, { withdraw: true, amount: "0.01" });
  say(`withdrawn to a fresh address of B, ${to}`);
}

await b.close();
server.kill();

// The route with Nym unreachable, in headless Chromium with its whole net log kept. A proxy script
// sends every Nym host the release lists to a closed port, and everything else the way it would
// go without one, so the tunnel cannot start. The test makes a
// wallet, reads the public account and checks that the page asks before going direct: "Stay on
// Nym" fails the read and asks nothing more for it, "Connect directly" lets it through, and no
// RPC host is named in the net log before that answer. Then Settings turns Nym off.
//
//   node web/tests/route.mjs <site dir> <scratch dir>
//
// A throwaway wallet's words are kept in <scratch dir> for the run and deleted after it.

import { readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { chromium } from "playwright";
import { open, serve } from "./journey/harness.mjs";
import { netHosts } from "./netlog.mjs";

const [site, scratch] = process.argv.slice(2);
const port = 8833;
const manifest = JSON.parse(readFileSync(join(site, "release-manifest.json"), "utf8"));
// The directory's hosts. With them blocked no tunnel can learn a gateway, as when Nym is out of
// reach; the policy's wildcard gateway sources name no host to block.
const nymHosts = manifest.mixnet
  .filter((s) => s.startsWith("https://"))
  .map((s) => new URL(s).hostname);
const log = join(scratch, "route-netlog.json");
const words = join(scratch, "route.words");
const say = (fact) => console.log(`${new Date().toISOString()} ${fact}`);
const problems = [];

// A machine whose way out is a proxy keeps it for every host but Nym's.
const onward = process.env.HTTPS_PROXY
  ? `PROXY ${new URL(process.env.HTTPS_PROXY).host}`
  : "DIRECT";
const pac = `function FindProxyForURL(url, host) {
  if (${JSON.stringify(nymHosts)}.indexOf(host) >= 0) return "PROXY 127.0.0.1:9";
  if (host === "localhost" || host === "127.0.0.1") return "DIRECT";
  return "${onward}";
}`;

const server = await serve(site, port);
const browser = await chromium.launch({
  executablePath: "/opt/pw-browsers/chromium",
  headless: true,
  args: [
    `--log-net-log=${log}`,
    `--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,${Buffer.from(pac).toString("base64")}`,
  ],
});
let direct = Infinity;
try {
  const w = await open(browser, `http://localhost:${port}`, words);
  const { page } = w;
  const asked = page.getByRole("alertdialog");
  const status = () => page.locator("footer.status").textContent();
  if (!(await status()).includes("nym mixnet")) problems.push("the status line does not say nym");

  let started = Date.now();
  await w.click("Read again");
  await asked.waitFor({ timeout: 5 * 60 * 1000 });
  say(`asked after ${((Date.now() - started) / 1000).toFixed(1)} s`);
  const question = await asked.textContent();
  if (!question.includes("Nym isn't reachable. Connect directly?"))
    problems.push(`the question reads: ${question}`);
  if (!question.includes("Your IP address becomes visible to the network provider."))
    problems.push("the question does not say the IP address becomes visible");
  await w.click("Stay on Nym");
  await page.getByRole("alert").getByText("The network could not be reached").waitFor();
  const again = await asked.waitFor({ timeout: 20_000 }).then(
    () => true,
    () => false,
  );
  if (again) problems.push("the read asked again after Stay on Nym");
  say("Stay on Nym: the read failed and asked nothing more");

  started = Date.now();
  await w.page.getByRole("button", { name: "Dismiss", exact: true }).click();
  await w.click("Read again");
  const read = page.getByText("Read from a public endpoint");
  let answers = 0;
  while (!(await read.count())) {
    const next = await Promise.race([
      asked.waitFor({ timeout: 5 * 60 * 1000 }).then(() => "asked"),
      read.waitFor({ timeout: 5 * 60 * 1000 }).then(() => "read"),
    ]);
    if (next === "read") break;
    if (direct === Infinity) direct = Date.now();
    await w.click("Connect directly");
    answers += 1;
  }
  say(`Connect directly: read after ${answers} answer(s), ${(Date.now() - started) / 1000} s`);

  await w.click("Settings");
  await w.heading("Settings");
  const row = await page.locator("dl.facts").textContent();
  if (!row.includes("Nym mixnet")) problems.push("Settings does not show the Nym route");
  await w.click("Nym mixnet: on");
  await page.getByRole("button", { name: "Nym mixnet: off", exact: true }).waitFor();
  if (!(await page.locator("dl.facts").textContent()).includes("browser, direct"))
    problems.push("Settings does not show the direct route once Nym is off");
  if (!(await status()).includes("browser, direct"))
    problems.push("the status line does not say direct once Nym is off");
  await w.click("Back");
  await w.heading("Wallet");
  await w.click("Read again");
  const quiet = await Promise.race([
    asked.waitFor({ timeout: 120_000 }).then(() => false),
    page
      .getByRole("alert")
      .waitFor({ timeout: 120_000 })
      .then(() => true),
    page.waitForTimeout(30_000).then(() => true),
  ]);
  if (!quiet) problems.push("Nym off still asked");
  say("Nym off in Settings: the read went direct without asking");
} finally {
  await browser.close();
  server.kill();
  rmSync(words, { force: true });
}

const hosts = netHosts(log);
const before = [...hosts].filter(([, t]) => t < direct).map(([h]) => h);
const rpcBefore = before.filter((h) => manifest.connect.includes(h));
const rpcAfter = [...hosts].filter(([h, t]) => t >= direct && manifest.connect.includes(h));
say(`hosts named before the first direct answer: ${before.sort().join(" ")}`);
say(`RPC hosts named after it: ${rpcAfter.map(([h]) => h).join(" ")}`);
if (rpcBefore.length) problems.push(`RPC hosts before the answer: ${rpcBefore.join(" ")}`);
if (!rpcAfter.length) problems.push("no RPC host after the answer, so the log missed them");
if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
say("pass");

// Make or restore the two journey wallets and print their public addresses, the only thing about
// them that leaves this machine. The first is the one to fund with Sepolia ETH.
//
//   node web/tests/journey/addresses.mjs <site dir> <words file A> <words file B>

import { browser, open, serve } from "./harness.mjs";

const [site, wordsA, wordsB] = process.argv.slice(2);
const port = 8820;
const server = await serve(site, port);
const b = await browser();
for (const [name, file] of [
  ["A", wordsA],
  ["B", wordsB],
]) {
  const w = await open(b, `http://localhost:${port}`, file);
  await w.click("Receive");
  await w.heading("Receive");
  await w.page.locator("img.qr").waitFor();
  await w.click("Receive at the 0x address");
  await w.page.locator(".address").filter({ hasText: /^0x/ }).waitFor();
  console.log(`wallet ${name}: ${await w.page.locator(".address").textContent()}`);
  await w.page.context().close();
}
await b.close();
server.kill();

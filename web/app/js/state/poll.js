// Ask the network about a sent transaction until it is mined or the page stops caring. Each check
// is one request to the endpoint that took the transaction. A block comes about every twelve
// seconds, so the first minute checks every four, to say so within a few seconds of it landing,
// and after that every twelve.

const SOON = 4_000;
const EVERY = 12_000;
const FIRST_MINUTE = 60_000;
const LIMIT = 30 * 60_000;

export async function untilMined(app, network, hash, onStatus, onCheck = () => {}) {
  const start = Date.now();
  while (Date.now() - start < LIMIT) {
    const asked = Date.now();
    const status = await app.call("publicSendStatus", network, hash).catch(() => "pending");
    onCheck((Date.now() - asked) / 1000);
    onStatus(status);
    if (status !== "pending") return status;
    const wait = Date.now() - start < FIRST_MINUTE ? SOON : EVERY;
    await new Promise((r) => setTimeout(r, wait));
  }
  return "pending";
}

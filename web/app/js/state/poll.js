// Ask the network about a sent transaction until it is mined or the page stops caring. Each check
// is one request to the endpoint that took the transaction.

const EVERY = 12_000;
const TIMES = 150;

export async function untilMined(app, network, hash, onStatus) {
  for (let i = 0; i < TIMES; i++) {
    const status = await app.call("publicSendStatus", network, hash).catch(() => "pending");
    onStatus(status);
    if (status !== "pending") return status;
    await new Promise((r) => setTimeout(r, EVERY));
  }
  return "pending";
}

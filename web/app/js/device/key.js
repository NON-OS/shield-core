// Ask the passkey for the wallet's secret and hand it to the core for the call that follows.
// A cancelled prompt is reported in the apps' plain words, and nothing changes.

import { passkey } from "./passkey.js";
import { PasskeyRefused } from "./refused.js";

export async function giveKey(app) {
  const id = await app.store.meta("passkey");
  if (!id) throw new PasskeyRefused("No passkey guards a wallet in this browser.");
  let secret;
  try {
    secret = await passkey.secret(id);
  } catch {
    throw new PasskeyRefused("The passkey was not used. Nothing changed.");
  }
  if (!secret) throw new PasskeyRefused("That passkey cannot give the wallet its key.");
  await app.wallet.holdKey(secret);
}

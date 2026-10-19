// Make the passkey a new wallet is sealed under, and hand its secret to the core.

import { passkey } from "./passkey.js";
import { giveKey } from "./key.js";
import { PasskeyRefused } from "./refused.js";

export async function newKey(app) {
  let id;
  try {
    id = await passkey.create();
  } catch {
    throw new PasskeyRefused("No passkey was made. Nothing changed.");
  }
  if (!id) {
    throw new PasskeyRefused(
      "That passkey cannot derive a secret, so it cannot guard the wallet. Try another authenticator.",
    );
  }
  await app.store.setMeta("passkey", id);
  await giveKey(app);
}

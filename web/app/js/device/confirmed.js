// Before money moves, the owner is asked to verify with the passkey, where the apps ask for Face ID
// or the screen lock. Only the verification is used; the secret it derives is wiped at once.

import { passkey } from "./passkey.js";
import { PasskeyRefused } from "./refused.js";

export async function confirmed(app) {
  const id = await app.store.meta("passkey");
  const secret = id ? await passkey.secret(id).catch(() => null) : null;
  if (!secret) throw new PasskeyRefused("Not confirmed. Nothing was sent.");
  secret.fill(0);
}

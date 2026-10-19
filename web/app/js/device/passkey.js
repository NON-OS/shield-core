// The passkey that guards the wallet. Its PRF extension derives a 32-byte secret from a salt this
// page fixes, inside the authenticator and only after the user is verified; the core wraps the
// wallet's file key under it. Nothing here is sent anywhere: there is no server to check an
// assertion, and none is needed, since the secret is the only thing used.

const NAME = "NØNOS Wallet";

async function salt() {
  const text = new TextEncoder().encode("nox-shield/web/vault-key/v1");
  return new Uint8Array(await crypto.subtle.digest("SHA-256", text));
}

const random = (n) => crypto.getRandomValues(new Uint8Array(n));

export const passkey = {
  /** Whether this browser offers passkeys with PRF, as far as it will say before one is made. */
  async supported() {
    if (!window.PublicKeyCredential || !navigator.credentials?.create) return false;
    const caps = await PublicKeyCredential.getClientCapabilities?.().catch(() => null);
    // Browsers that cannot report capabilities may still have PRF; making the passkey settles it.
    return caps ? caps["extension:prf"] !== false : true;
  },

  /** Make a passkey for this wallet. Resolves to its id, or null when it has no PRF. */
  async create() {
    const credential = await navigator.credentials.create({
      publicKey: {
        rp: { name: NAME, id: location.hostname },
        user: { id: random(16), name: NAME, displayName: NAME },
        challenge: random(32),
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
        extensions: { prf: {} },
      },
    });
    const prf = credential.getClientExtensionResults().prf;
    return prf?.enabled ? new Uint8Array(credential.rawId) : null;
  },

  /** The secret of the passkey `id`, after the user is verified, or null without PRF. */
  async secret(id) {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: random(32),
        rpId: location.hostname,
        allowCredentials: [{ type: "public-key", id }],
        userVerification: "required",
        extensions: { prf: { eval: { first: await salt() } } },
      },
    });
    const first = assertion.getClientExtensionResults().prf?.results?.first;
    return first ? new Uint8Array(first) : null;
  },
};

import { h } from "./h.js";

/** Which network a screen acts on, in the apps' words. Mainnet is filled, so it cannot be missed. */
export function networkBanner(network) {
  const real = network === "mainnet";
  return h(
    "p",
    { class: real ? "network real" : "network", role: "note" },
    real ? "REAL MONEY · ETHEREUM MAINNET" : "TEST NETWORK · SEPOLIA",
  );
}

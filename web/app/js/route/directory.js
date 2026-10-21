// The entry gateways a tunnel may start through, from Nym's own directory, read when a tunnel
// starts. A gateway qualifies when it lists a host name and a wss port the page may open, and a
// performance of at least 0.9 by the directory's own measure. One is drawn at random, weighted by
// that performance, so the users of the page spread over every usable gateway.

import { nymHosts } from "./hosts.js";

const PATH = "/api/v1/unstable/nym-nodes/skimmed/entry-gateways/all";
const LEAST = 0.9;
const READ_MS = 20_000;

async function listing() {
  let last = new Error("Nym's directory gave no answer");
  for (const api of nymHosts.api) {
    try {
      const res = await fetch(`https://${api}${PATH}`, {
        cache: "no-store",
        signal: AbortSignal.timeout(READ_MS),
      });
      if (!res.ok) throw new Error(`Nym's directory answered ${res.status}`);
      const body = await res.json();
      return body.nodes?.data ?? body.nodes ?? [];
    } catch (e) {
      last = e;
    }
  }
  throw last;
}

/** Every usable entry gateway the directory lists now, with its weight. */
export async function entryGateways() {
  return (await listing())
    .map((n) => ({
      id: n.ed25519_identity_pubkey,
      host: n.entry?.hostname,
      port: n.entry?.wss_port,
      weight: Number(n.performance),
    }))
    .filter((g) => g.id && g.host && nymHosts.ports.includes(g.port) && g.weight >= LEAST);
}

/** One gateway drawn at random by weight, from those not in `skip`. */
export function draw(gateways, skip) {
  const open = gateways.filter((g) => !skip.has(g.id));
  if (!open.length) throw new Error("no Nym gateway the directory lists is left to try");
  const total = open.reduce((sum, g) => sum + g.weight, 0);
  let at = (crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32) * total;
  for (const g of open) {
    at -= g.weight;
    if (at < 0) return g;
  }
  return open[open.length - 1];
}

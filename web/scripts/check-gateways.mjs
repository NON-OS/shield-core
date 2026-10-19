// Say which pinned gateways Nym's directory still lists as a usable entry: the same identity, the
// same host, wss on the pinned port and a performance of at least 0.9. Run it before a release;
// it exits 1 when fewer than half the pinned set qualify, which is the time to pin again.
//
//   node web/scripts/check-gateways.mjs

import { nymHosts } from "../app/js/route/hosts.js";

const url = `https://${nymHosts.api[0]}/api/v1/unstable/nym-nodes/skimmed/entry-gateways/all`;
const res = await fetch(url);
if (!res.ok) throw new Error(`the directory answered ${res.status}`);
const listing = await res.json();
const nodes = new Map(
  (listing.nodes?.data ?? listing.nodes).map((n) => [n.ed25519_identity_pubkey, n]),
);
let usable = 0;
for (const { id, host } of nymHosts.gateways) {
  const n = nodes.get(id);
  const fine =
    n?.entry?.hostname === host &&
    n.entry.wss_port === nymHosts.port &&
    Number(n.performance) >= 0.9;
  if (fine) usable += 1;
  console.log(
    `${fine ? "usable" : "not usable"}  ${host}  ${n ? `performance ${n.performance}` : "not listed"}`,
  );
}
console.log(`${usable} of ${nymHosts.gateways.length} pinned gateways are usable`);
process.exit(usable * 2 >= nymHosts.gateways.length ? 0 : 1);

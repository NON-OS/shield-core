// Say how many entry gateways Nym's directory lists as usable by the page now, as a tunnel would
// choose them: a host name, a wss port the policy allows and a performance of at least 0.9. It
// exits 1 below a floor, when the page would have too few gateways to spread its users over.
//
//   node web/scripts/check-gateways.mjs

import { entryGateways } from "../app/js/route/directory.js";

const FLOOR = 50;
const gateways = await entryGateways();
const ports = new Map();
for (const g of gateways) ports.set(g.port, (ports.get(g.port) ?? 0) + 1);
console.log(
  `${gateways.length} usable entry gateways, by wss port: ${[...ports].map(([p, n]) => `${p} ${n}`).join(", ")}`,
);
process.exit(gateways.length >= FLOOR ? 0 : 1);

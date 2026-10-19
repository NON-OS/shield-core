import { h } from "../ui/h.js";

const row = (name, value) =>
  h(
    "div",
    { class: "tile-row" },
    h("span", { class: "name" }, name),
    h("span", { class: "value" }, value),
  );

/** The quote's terms and its route, row by row as the apps list them. */
export function swapTerms(s) {
  const nox = s.from === "nox" || s.to === "nox";
  return h(
    "section",
    { class: "tile", "aria-label": "Terms" },
    row("Rate", s.rate),
    row("Minimum received", `${s.minimumOut} ${s.to.toUpperCase()}`),
    row("Price impact", `${s.priceImpactPercent}%`),
    row("Max slippage", `${s.slippagePercent}%`),
    row("Route", s.route),
    row("Venue", s.venue),
    s.pools.map((pool) => row(s.pools.length > 1 ? "Pool, 0.3% each" : "Pool, 0.3%", pool)),
    nox && row("NOX token fee", `${s.tokenFee} NOX`),
    row("Network fee, at most", `${s.maxNetworkFee} ETH`),
    row("Nonce, chain", `${s.nonce}, ${s.chainId}`),
  );
}

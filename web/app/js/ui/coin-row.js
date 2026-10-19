import { h } from "./h.js";
import { coinLogo } from "./coin-logo.js";

/** A coin with its mark, its name and a note under it, and the amount held. */
export function coinRow(coin, amount, note) {
  return h(
    "div",
    { class: "coin-row" },
    h("span", { class: "logo" }, coinLogo(coin)),
    h(
      "span",
      { class: "names" },
      h("span", { class: "symbol" }, coin.toUpperCase()),
      note && h("span", { class: "note" }, note),
    ),
    h("span", { class: "amount" }, amount),
  );
}

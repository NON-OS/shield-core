import { h } from "./h.js";
import { field } from "./field.js";

// The first standard sizes of each coin: 1, 2 or 5 followed by zeros, from the smallest the pool
// takes. More can be typed; these are the ones most spends use.
const SIZES = {
  nox: ["1000", "2000", "5000", "10000", "20000", "50000"],
  eth: ["0.01", "0.02", "0.05", "0.1", "0.2", "0.5"],
};

const shown = (v) => (Number(v) >= 1000 ? Number(v).toLocaleString("en-US") : v);

/**
 * An amount in one of the pool's standard sizes, typed or picked from the first few. A chip is
 * marked pressed while the field holds its amount. Returns the field with `.input` on it.
 */
export function amountField(coin, { value = "" } = {}) {
  const unit = coin.toUpperCase();
  const wrap = field(`Amount in ${unit}`, {
    inputmode: "decimal",
    value,
    hint: "Standard sizes only: 1, 2 or 5 followed by zeros.",
  });
  const chips = (SIZES[coin] ?? []).map((size) =>
    h(
      "button",
      {
        type: "button",
        class: "chip",
        "aria-pressed": "false",
        onclick: () => {
          wrap.input.value = size;
          mark();
          wrap.input.dispatchEvent(new Event("input", { bubbles: true }));
        },
      },
      shown(size),
    ),
  );
  const mark = () => {
    const v = wrap.input.value.replace(/,/g, "").trim();
    chips.forEach((c, i) => c.setAttribute("aria-pressed", String(SIZES[coin][i] === v)));
  };
  wrap.input.addEventListener("input", mark);
  mark();
  wrap.input.after(
    h("div", { class: "chips", role: "group", "aria-label": `Standard amounts in ${unit}` }, chips),
  );
  return wrap;
}

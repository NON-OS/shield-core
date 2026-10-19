import { h } from "./h.js";
import { quiet } from "./quiet.js";
import { standardBelow } from "../text/standard-below.js";

/**
 * While a deposit's note is unspent, a line that says the words do not restore it, and the way to
 * fix that: a private send to this wallet's own address, whose notes are sealed to its key.
 */
export function depositReminder(app) {
  const held = (app.depositNotes ?? []).find((b) => b.spendable > 0 || b.pending > 0);
  if (!held) return null;
  const coin = held.coin;
  const amount = held.spendable > 0 ? standardBelow(held.spendableText) : null;
  return h(
    "section",
    { class: "failure", "aria-label": "Deposits kept on this device only" },
    h(
      "p",
      { class: "lead" },
      `${held.spendable > 0 ? held.spendableText : held.pendingText} ${coin.toUpperCase()} in deposit notes is kept only in this browser. The recovery words do not bring it back until it is sent privately, to anyone or to this wallet itself.`,
    ),
    amount &&
      quiet([
        [
          "Make it recoverable",
          () => app.show("spend", { withdraw: false, self: true, coin, amount, entered: true }),
        ],
      ]),
  );
}

import { h } from "./h.js";
import { quiet } from "./quiet.js";
import { standardWithin } from "../text/standard-within.js";

/**
 * While a deposit's note is unspent, a line that says the words do not restore it, and the way to
 * fix that: a private send to this wallet's own address, whose notes are sealed to its key.
 */
export function depositReminder(app) {
  const held = (app.depositNotes ?? []).find((b) => b.spendable > 0 || b.pending > 0);
  if (!held) return null;
  const coin = held.coin;
  // The pool's smallest sizes, and twice the fee's fixed part as room for its network part.
  const least = { eth: "0.01", nox: "1000" }[coin];
  const fee = app.relayFees?.[coin];
  const room = fee && String(Number(fee.replace(/,/g, "")) * 2);
  const amount =
    held.spendable > 0 && room ? standardWithin(held.spendableText, room, least) : null;
  return h(
    "section",
    { class: "failure", "aria-label": "Deposits kept on this device only" },
    h(
      "p",
      { class: "lead" },
      `${held.spendable > 0 ? held.spendableText : held.pendingText} ${coin.toUpperCase()} in deposit notes is kept only in this browser. The recovery words do not bring it back until it is sent privately, to anyone or to this wallet itself.`,
    ),
    held.spendable > 0 &&
      !amount &&
      h(
        "p",
        { class: "lead" },
        "The note is too small to send alone with the fee. A later deposit can be sent together with it.",
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
